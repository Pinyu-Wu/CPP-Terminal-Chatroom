#include <iostream>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <cstring>
#include <string_view>
#include <thread>
#include <cstdlib>
#include <sodium.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <mutex>
#include <unordered_map>
#include <queue>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <vector>
#include <errno.h>
#include <chrono>
#include <cstdint>

#include "UserManager.hpp"
#include "ChatManager.hpp"
#include "json.hpp"
#include "utils.hpp"
#include "RateLimiter.hpp"
#include "ThreadPool.hpp"
#include "FdWrapper.hpp"
#include "Logging.hpp"
#include "Metrics.hpp"
#include "Framing.hpp"

using json = nlohmann::json;

namespace
{
    // Standardized error codes for client-side handling.
    constexpr const char *ERR_BAD_REQUEST = "ERR_BAD_REQUEST";
    constexpr const char *ERR_INVALID_AUTH = "ERR_INVALID_AUTH";
    constexpr const char *ERR_AUTH_RATE_LIMIT = "ERR_AUTH_RATE_LIMIT";
    constexpr const char *ERR_RATE_LIMIT = "ERR_RATE_LIMIT";
    constexpr const char *ERR_USER_NOT_FOUND = "ERR_USER_NOT_FOUND";
    constexpr const char *ERR_WRONG_PASSWORD = "ERR_WRONG_PASSWORD";
    constexpr const char *ERR_USER_EXISTS = "ERR_USER_EXISTS";
    constexpr const char *ERR_ALREADY_LOGGED_IN = "ERR_ALREADY_LOGGED_IN";
    constexpr const char *ERR_INVALID_USERNAME = "ERR_INVALID_USERNAME";
    constexpr const char *ERR_INVALID_MESSAGE = "ERR_INVALID_MESSAGE";
    constexpr const char *ERR_NOT_FRIEND = "ERR_NOT_FRIEND";
    constexpr const char *ERR_UNKNOWN_ACTION = "ERR_UNKNOWN_ACTION";
    constexpr const char *ERR_JSON_PARSE = "ERR_JSON_PARSE";
    constexpr const char *ERR_INTERNAL = "ERR_INTERNAL";

    constexpr std::size_t MAX_FRAME_SIZE = 1 << 20; // 1 MB per message.

    constexpr const char *USERS_PATH = "data/users.json";
    constexpr const char *CHAT_HISTORY_PATH = "data/chat_history.json";
    constexpr const char *CERT_PATH = "config/cert.pem";
    constexpr const char *KEY_PATH = "config/key.pem";
}

UserManager userManager;
ChatManager chatManager;
std::unordered_map<int, std::shared_ptr<User>> active_sessions;
std::unordered_map<std::string, int> user_to_socket;
std::mutex session_mutex; // Guards active_sessions and user_to_socket.
std::mutex user_mutex;    // Serializes access to userManager.

Metrics metrics;

// Rate limiters for general and auth-only requests.
RateLimiter requestLimiter(20, std::chrono::seconds(1));
RateLimiter authLimiter(10, std::chrono::seconds(10));

struct Connection
{
    Fd fd;
    SslPtr ssl;
    bool handshaked = false;
    bool authenticated = false;
    std::string username;
    std::string send_buffer;
    std::string peer; // IP:port
    std::string recv_buffer;
};

std::unordered_map<int, Connection> connections;
std::mutex connections_mutex;

struct Outgoing
{
    int fd;
    std::string data;
};
std::queue<Outgoing> outgoing_queue;
std::mutex outgoing_mutex;

enum class SendResult
{
    Ok,      // All data sent.
    Pending, // Awaiting more I/O.
    Error
};

#ifdef ENABLE_TEST_CRASH
static void force_test_crash()
{
    std::cerr << "[TEST_CRASH] Intentionally crashing for core dump verification\n";
    volatile int *ptr = nullptr;
    *ptr = 1; // Intentional SIGSEGV for crash testing.
}
#endif

static void enqueue_response(int fd, const json &j);
static void send_disconnect(SSL *ssl, const char *error, const char *message)
{
    if (!ssl)
        return;
    json resp;
    resp["action"] = "disconnect";
    resp["status"] = "fail";
    if (error)
        resp["error"] = error;
    if (message)
        resp["message"] = message;
    std::string payload = resp.dump();
    std::string framed = frame_message(payload);
    const char *data = framed.data();
    std::size_t remaining = framed.size();
    while (remaining > 0)
    {
        int written = SSL_write(ssl, data, static_cast<int>(remaining));
        if (written <= 0)
            break;
        data += written;
        remaining -= static_cast<std::size_t>(written);
    }
}

static void respond_fail(int fd, std::string_view error, std::string_view message)
{
    json resp;
    resp["status"] = "fail";
    resp["error"] = error;
    resp["message"] = message;
    enqueue_response(fd, resp);
}

static void respond_ok(int fd, json payload = json::object())
{
    payload["status"] = "success";
    enqueue_response(fd, payload);
}

static SendResult send_buffered(Connection &conn)
{
    while (!conn.send_buffer.empty())
    {
        int ret = SSL_write(conn.ssl.get(), conn.send_buffer.data(), static_cast<int>(conn.send_buffer.size()));
        if (ret > 0)
        {
            conn.send_buffer.erase(0, static_cast<std::size_t>(ret));
            continue;
        }
        int err = SSL_get_error(conn.ssl.get(), ret);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
        {
            return SendResult::Pending; // Still has pending data.
        }
        return SendResult::Error; // Caller will close the connection.
    }
    return SendResult::Ok;
}

static void enqueue_response(int fd, const json &j)
{
    std::string payload = j.dump();
    std::string data = frame_message(payload);
    std::lock_guard<std::mutex> lock(outgoing_mutex);
    outgoing_queue.push({fd, std::move(data)});
}

static int set_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1)
        return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static void close_connection(Epoll &epoll, int fd, const char *error = nullptr, const char *message = nullptr)
{
    bool had_connection = false;
    std::string peer_info;
    {
        std::lock_guard<std::mutex> lock(connections_mutex);
        auto it = connections.find(fd);
        if (it != connections.end())
        {
            had_connection = true;
            peer_info = it->second.peer;
            if (error || message)
            {
                send_disconnect(it->second.ssl.get(), error, message);
            }
            if (it->second.ssl)
            {
                SSL_shutdown(it->second.ssl.get());
            }
            connections.erase(it); // Fd/SslPtr destructors handle cleanup.
        }
    }
    if (had_connection)
    {
        metrics.dec_connections();
    }
    epoll.del(fd);
    std::string username_to_remove;
    {
        std::lock_guard<std::mutex> lock(session_mutex);
        auto it = active_sessions.find(fd);
        if (it != active_sessions.end())
        {
            username_to_remove = it->second->getUsername();
            active_sessions.erase(it);
        }
        if (!username_to_remove.empty())
        {
            user_to_socket.erase(username_to_remove);
        }
    }
    if (had_connection)
    {
        nlohmann::json extra = {{"fd", fd}};
        if (!peer_info.empty())
            extra["peer"] = peer_info;
        if (!username_to_remove.empty())
            extra["user"] = username_to_remove;
        if (error)
            extra["error"] = error;
        if (message)
            extra["reason"] = message;
        Logger::log_event(LogLevel::Info, "connection_close", "Client disconnected", extra);
    }
}

static bool handle_authentication(int fd, const json &request, const std::string &action, std::string &error_code)
{
    error_code.clear();
    if (!request.contains("username") || !request["username"].is_string() ||
        !request.contains("password") || !request["password"].is_string())
    {
        respond_fail(fd, ERR_BAD_REQUEST, "Invalid username or password format.");
        error_code = ERR_BAD_REQUEST;
        return false;
    }

    std::string user = request["username"];
    std::string pw = request["password"];

    if (!isValidUsername(user) || !isValidPassword(pw))
    {
        respond_fail(fd, ERR_INVALID_AUTH, "Invalid username or password.");
        error_code = ERR_INVALID_AUTH;
        return false;
    }

    if (action == "login")
    {
        std::lock_guard<std::mutex> user_lock(user_mutex);
        if (!userManager.userExists(user))
        {
            respond_fail(fd, ERR_USER_NOT_FOUND, "User not found.");
            error_code = ERR_USER_NOT_FOUND;
        }
        else if (!userManager.verifyPassword(user, pw))
        {
            respond_fail(fd, ERR_WRONG_PASSWORD, "Wrong password.");
            error_code = ERR_WRONG_PASSWORD;
        }
        else
        {
            {
                std::lock_guard<std::mutex> session_lock(session_mutex);
                auto it = user_to_socket.find(user);
                if (it != user_to_socket.end() && it->second != fd)
                {
                    respond_fail(fd, ERR_ALREADY_LOGGED_IN, "User already logged in.");
                    error_code = ERR_ALREADY_LOGGED_IN;
                    return false;
                }
            }
            {
                std::lock_guard<std::mutex> lock(connections_mutex);
                auto it = connections.find(fd);
                if (it != connections.end())
                {
                    it->second.username = user;
                    it->second.authenticated = true;
                }
            }
            {
                std::lock_guard<std::mutex> session_lock(session_mutex);
                auto user_ptr = userManager.getUser(user);
                active_sessions[fd] = user_ptr;
                user_to_socket[user] = fd;
            }
            respond_ok(fd);
            return true;
        }
    }
    else if (action == "register")
    {
        std::lock_guard<std::mutex> user_lock(user_mutex);
        if (userManager.userExists(user))
        {
            respond_fail(fd, ERR_USER_EXISTS, "User already exists.");
            error_code = ERR_USER_EXISTS;
        }
        else if (!userManager.registerUser(user, pw))
        {
            respond_fail(fd, ERR_INTERNAL, "Register failed.");
            error_code = ERR_INTERNAL;
        }
        else
        {
            userManager.saveToFile(USERS_PATH);
            {
                std::lock_guard<std::mutex> lock(connections_mutex);
                auto it = connections.find(fd);
                if (it != connections.end())
                {
                    it->second.username = user;
                    it->second.authenticated = true;
                }
            }
            {
                std::lock_guard<std::mutex> session_lock(session_mutex);
                auto user_ptr = userManager.getUser(user);
                active_sessions[fd] = user_ptr;
                user_to_socket[user] = fd;
            }
            respond_ok(fd);
            return true;
        }
    }
    else
    {
        respond_fail(fd, ERR_UNKNOWN_ACTION, "Unknown action.");
        error_code = ERR_UNKNOWN_ACTION;
    }
    return false;
}

static void process_request(int fd, const json &request)
{
    std::string username;
    bool authenticated = false;
    {
        std::lock_guard<std::mutex> lock(connections_mutex);
        auto it = connections.find(fd);
        if (it == connections.end())
            return;
        username = it->second.username;
        authenticated = it->second.authenticated;
    }

    std::string action = request["action"];
    auto start_time = std::chrono::steady_clock::now();
    bool recorded = false;
    // One-shot tail handler to record metrics and structured logs.
    auto finish = [&](const std::string &status, const std::string &error_code)
    {
        if (recorded)
            return;
        recorded = true;
        auto latency = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - start_time);
        metrics.inc_request(action);
        metrics.observe_latency(action, latency);

        nlohmann::json extra = {
            {"action", action},
            {"status", status},
            {"latency_ms", latency.count() / 1000.0},
            {"authenticated", authenticated}};
        if (!username.empty())
            extra["user"] = username;
        if (!error_code.empty())
            extra["error"] = error_code;

        Logger::log_event(status == "success" ? LogLevel::Info : LogLevel::Warn,
                          "request", "Handled request", extra);
    };

    if (!authenticated)
    {
        std::string auth_error;
        bool ok = handle_authentication(fd, request, action, auth_error);
        finish(ok ? "success" : "fail", auth_error);
        return;
    }

    // Authenticated actions.
    if (action == "addfriend")
    {
        if (!request.contains("target") || !request["target"].is_string())
        {
            respond_fail(fd, ERR_BAD_REQUEST, "Invalid target.");
            finish("fail", ERR_BAD_REQUEST);
            return;
        }
        std::string target = request["target"];

        if (!isValidUsername(target))
        {
            respond_fail(fd, ERR_INVALID_USERNAME, "Invalid username.");
            finish("fail", ERR_INVALID_USERNAME);
        }
        else
        {
            std::lock_guard<std::mutex> user_lock(user_mutex);
            if (!userManager.userExists(target))
            {
                respond_fail(fd, ERR_USER_NOT_FOUND, "User '" + target + "' not found.");
                finish("fail", ERR_USER_NOT_FOUND);
            }
            else if (target == username)
            {
                respond_fail(fd, ERR_BAD_REQUEST, "You cannot add yourself.");
                finish("fail", ERR_BAD_REQUEST);
            }
            else
            {
                auto user_ptr = userManager.getUser(username);
                if (user_ptr->addFriend(target))
                {
                    userManager.saveToFile(USERS_PATH);
                    json payload;
                    payload["action"] = "result";
                    payload["message"] = "You added '" + target + "' as a friend.";
                    respond_ok(fd, payload);
                    finish("success", "");
                }
                else
                {
                    respond_fail(fd, ERR_BAD_REQUEST, "'" + target + "' is already your friend.");
                    finish("fail", ERR_BAD_REQUEST);
                }
            }
        }
    }
    else if (action == "listfriends")
    {
        std::shared_ptr<User> user_ptr;
        {
            std::lock_guard<std::mutex> user_lock(user_mutex);
            user_ptr = userManager.getUser(username);
        }
        if (user_ptr)
        {
            json payload;
            payload["action"] = "listfriends";
            payload["friendlist"] = user_ptr->getFriends();
            respond_ok(fd, payload);
            finish("success", "");
        }
        else
        {
            respond_fail(fd, ERR_INTERNAL, "User not found in memory.");
            finish("fail", ERR_INTERNAL);
        }
    }
    else if (action == "normal")
    {
        if (!request.contains("message") || !request["message"].is_string())
        {
            respond_fail(fd, ERR_BAD_REQUEST, "Invalid message.");
            finish("fail", ERR_BAD_REQUEST);
        }
        else
        {
            std::string msg = request["message"];
            if (!isValidMessage(msg))
            {
                respond_fail(fd, ERR_INVALID_MESSAGE, "Invalid message content.");
                finish("fail", ERR_INVALID_MESSAGE);
            }
            else
            {
                json payload;
                payload["action"] = "echo";
                payload["message"] = msg;
                respond_ok(fd, payload);
                finish("success", "");
            }
        }
    }
    else if (action == "chat_request")
    {
        if (!request.contains("target") || !request["target"].is_string())
        {
            respond_fail(fd, ERR_BAD_REQUEST, "Invalid target.");
            finish("fail", ERR_BAD_REQUEST);
            return;
        }
        std::string target = request["target"];
        if (!isValidUsername(target))
        {
            respond_fail(fd, ERR_INVALID_USERNAME, "Invalid username.");
            finish("fail", ERR_INVALID_USERNAME);
        }
        else
        {
            std::lock_guard<std::mutex> user_lock(user_mutex);
            if (!userManager.userExists(target))
            {
                respond_fail(fd, ERR_USER_NOT_FOUND, "User does not exist.");
                finish("fail", ERR_USER_NOT_FOUND);
            }
            else if (!userManager.getUser(username)->isFriend(target))
            {
                respond_fail(fd, ERR_NOT_FRIEND, "Not your friend.");
                finish("fail", ERR_NOT_FRIEND);
            }
            else
            {
                json payload;
                payload["action"] = "chat_response";
                payload["message"] = "OK";
                respond_ok(fd, payload);
                finish("success", "");
            }
        }
    }
    else if (action == "get_history")
    {
        if (!request.contains("target") || !request["target"].is_string())
        {
            respond_fail(fd, ERR_BAD_REQUEST, "Invalid target.");
            finish("fail", ERR_BAD_REQUEST);
            return;
        }
        std::string target = request["target"];
        if (!isValidUsername(target))
        {
            respond_fail(fd, ERR_INVALID_USERNAME, "Invalid username.");
            finish("fail", ERR_INVALID_USERNAME);
            return;
        }
        auto history = chatManager.getHistory(username, target);

        json history_array = json::array();
        for (const auto &msg : history)
        {
            history_array.push_back({{"from", msg.from},
                                     {"content", msg.content},
                                     {"timestamp", msg.timestamp}});
        }
        json payload;
        payload["action"] = "chat_history";
        payload["with"] = target;
        payload["history"] = history_array;
        respond_ok(fd, payload);
        finish("success", "");
    }
    else if (action == "chat_message")
    {
        if (!request.contains("target") || !request["target"].is_string() ||
            !request.contains("content") || !request["content"].is_string())
        {
            respond_fail(fd, ERR_BAD_REQUEST, "Invalid chat payload.");
            finish("fail", ERR_BAD_REQUEST);
            return;
        }
        std::string target = request["target"];
        std::string content = request["content"];
        if (!isValidUsername(target) || !isValidMessage(content))
        {
            respond_fail(fd, ERR_INVALID_MESSAGE, "Invalid chat content or target.");
            finish("fail", ERR_INVALID_MESSAGE);
            return;
        }

        json delivery;
        delivery["action"] = "chat_message";
        delivery["from"] = username;
        delivery["content"] = content;
        delivery["timestamp"] = current_timestamp();

        chatManager.addMessage(username, target, username, content);
        chatManager.saveToFile(CHAT_HISTORY_PATH);

        // Deliver immediately if the target is online.
        int target_fd = -1;
        {
            std::lock_guard<std::mutex> lock(session_mutex);
            if (user_to_socket.count(target))
                target_fd = user_to_socket[target];
        }
        if (target_fd != -1)
        {
            enqueue_response(target_fd, delivery);
        }
        else
        {
            std::cout << "💤 User " << target << " is offline. Message saved.\n";
        }

        json ack;
        ack["action"] = "chat_ack";
        ack["status"] = "sent";
        respond_ok(fd, ack);
        finish("success", "");
    }
    else
    {
        respond_fail(fd, ERR_UNKNOWN_ACTION, "Unknown action: " + action);
        finish("fail", ERR_UNKNOWN_ACTION);
    }

    if (!recorded)
    {
        finish("success", "");
    }
}

static void drain_outgoing_and_arm(Epoll &epoll)
{
    std::lock_guard<std::mutex> lock_out(outgoing_mutex);
    while (!outgoing_queue.empty())
    {
        auto item = std::move(outgoing_queue.front());
        outgoing_queue.pop();
        std::lock_guard<std::mutex> lock_conn(connections_mutex);
        auto it = connections.find(item.fd);
        if (it == connections.end())
            continue;
        it->second.send_buffer.append(item.data);
        epoll.mod(item.fd, EPOLLIN | EPOLLET | EPOLLOUT);
    }
}

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        std::cerr << "Usage: " << argv[0] << " <PORT>\n";
        return EXIT_FAILURE;
    }

    if (!userManager.loadFromFile(USERS_PATH))
    {
        std::cerr << "Failed to load " << USERS_PATH << "\n";
    }

    if (!chatManager.loadFromFile(CHAT_HISTORY_PATH))
    {
        std::cerr << "Failed to load " << CHAT_HISTORY_PATH << "\n";
    }
    if (sodium_init() < 0)
    {
        std::cerr << "Failed to init libsodium\n";
        return EXIT_FAILURE;
    }

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    SslCtxPtr ctx(SSL_CTX_new(TLS_server_method()));
    if (!ctx)
    {
        std::cerr << "Failed to create SSL_CTX\n";
        return EXIT_FAILURE;
    }

    if (SSL_CTX_use_certificate_file(ctx.get(), CERT_PATH, SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx.get(), KEY_PATH, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        return EXIT_FAILURE;
    }

    SSL_CTX_set_ecdh_auto(ctx.get(), 1);

    int port = std::atoi(argv[1]);

    sockaddr_in address{};
    socklen_t addrlen = sizeof(address);

    Fd server_fd(::socket(AF_INET, SOCK_STREAM, 0));
    if (!server_fd.valid())
    {
        perror("socket failed");
        return EXIT_FAILURE;
    }

    int opt = 1;
    setsockopt(server_fd.get(), SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);
    memset(address.sin_zero, '\0', sizeof(address.sin_zero));

    if (bind(server_fd.get(), (struct sockaddr *)&address, sizeof(address)) < 0)
    {
        perror("bind failed");
        return EXIT_FAILURE;
    }

    if (listen(server_fd.get(), 128) < 0)
    {
        perror("listen failed");
        return EXIT_FAILURE;
    }

    if (set_nonblocking(server_fd.get()) < 0)
    {
        perror("set_nonblocking failed");
        return EXIT_FAILURE;
    }

    Epoll epoll;
    if (!epoll.valid())
    {
        perror("epoll_create1");
        return EXIT_FAILURE;
    }

    epoll.add(server_fd.get(), EPOLLIN);

    ThreadPool pool(std::thread::hardware_concurrency());

    std::thread metrics_thread([]()
                               {
                                   while (true)
                                   {
                                       std::this_thread::sleep_for(std::chrono::seconds(10));
                                       auto snap = metrics.snapshot_and_reset_window();
                                       Logger::log_event(LogLevel::Info, "metrics_dump", "Periodic metrics snapshot", snap);
                                   } });
    metrics_thread.detach();

    std::cout << "Server listening on port " << port << "...\n";
#ifdef ENABLE_TEST_CRASH
    if (const char *crash_env = std::getenv("CHATROOM_FORCE_CRASH"))
    {
        if (std::string_view(crash_env) == "1")
        {
            std::cerr << "[TEST_CRASH] CHATROOM_FORCE_CRASH=1 set; forcing crash now\n";
            force_test_crash();
        }
    }
#endif
    std::vector<epoll_event> events(64);
    while (true)
    {
        drain_outgoing_and_arm(epoll);
        int n = epoll_wait(epoll.get(), events.data(), static_cast<int>(events.size()), 100);
        if (n < 0)
        {
            if (errno == EINTR)
                continue;
            perror("epoll_wait");
            break;
        }

        for (int i = 0; i < n; ++i)
        {
            int fd = events[i].data.fd;
            uint32_t evs = events[i].events;
            if (fd == server_fd.get())
            {
                while (true)
                {
                    int client_fd = accept(server_fd.get(), (struct sockaddr *)&address, &addrlen);
                    if (client_fd < 0)
                    {
                        if (errno == EAGAIN || errno == EWOULDBLOCK)
                            break;
                        perror("accept failed");
                        break;
                    }
                    Fd client_handle(client_fd);
                    if (set_nonblocking(client_handle.get()) < 0)
                    {
                        continue;
                    }

                    char client_ip[INET_ADDRSTRLEN] = {0};
                    inet_ntop(AF_INET, &address.sin_addr, client_ip, sizeof(client_ip));
                    int client_port = ntohs(address.sin_port);
                    std::string peer = std::string(client_ip) + ":" + std::to_string(client_port);

                    SslPtr ssl(SSL_new(ctx.get()));
                    if (!ssl)
                    {
                        continue;
                    }
                    SSL_set_fd(ssl.get(), client_handle.get());
                    SSL_set_accept_state(ssl.get());

                    Connection conn;
                    conn.fd = std::move(client_handle);
                    conn.ssl = std::move(ssl);
                    conn.peer = peer;

                    {
                        std::lock_guard<std::mutex> lock(connections_mutex);
                        connections[conn.fd.get()] = std::move(conn);
                    }

                    epoll_event client_ev{};
                    client_ev.events = EPOLLIN | EPOLLOUT | EPOLLET;
                    client_ev.data.fd = client_fd;
                    epoll.add(client_fd, client_ev.events);
                    metrics.inc_connections();
                    nlohmann::json extra = {{"fd", client_fd}, {"peer", peer}};
                    Logger::log_event(LogLevel::Info, "connection_open", "New client connected", extra);
                }
                continue;
            }

            Connection *conn_ptr = nullptr;
            {
                std::lock_guard<std::mutex> lock(connections_mutex);
                auto it = connections.find(fd);
                if (it != connections.end())
                    conn_ptr = &it->second;
            }
            if (!conn_ptr)
                continue;
            Connection &conn = *conn_ptr;

            if (evs & (EPOLLHUP | EPOLLERR))
            {
                std::cerr << "🔌 EPOLL hangup/error on fd " << fd << "\n";
                nlohmann::json extra = {{"fd", fd}, {"events", static_cast<int>(evs)}};
                Logger::log_event(LogLevel::Warn, "epoll_error", "EPOLL hangup/error", extra);
                close_connection(epoll, fd, ERR_INTERNAL, "EPOLL error or hangup.");
                continue;
            }

            // Complete the TLS handshake if needed.
            if (!conn.handshaked)
            {
                int ret = SSL_accept(conn.ssl.get());
                if (ret == 1)
                {
                    conn.handshaked = true;
                    nlohmann::json extra = {{"fd", fd}};
                    if (!conn.peer.empty())
                        extra["peer"] = conn.peer;
                    Logger::log_event(LogLevel::Info, "tls_handshake", "Handshake complete", extra);
                    epoll_event mod_ev{};
                    mod_ev.events = EPOLLIN | EPOLLET;
                    if (!conn.send_buffer.empty())
                        mod_ev.events |= EPOLLOUT;
                    mod_ev.data.fd = fd;
                    epoll.mod(fd, mod_ev.events);
                }
                else
                {
                    int err = SSL_get_error(conn.ssl.get(), ret);
                    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
                    {
                        // Need more I/O; wait for the next event.
                    }
                    else
                    {
                        nlohmann::json extra = {{"fd", fd}, {"ssl_error", err}};
                        if (!conn.peer.empty())
                            extra["peer"] = conn.peer;
                        Logger::log_event(LogLevel::Warn, "tls_handshake_fail", "TLS handshake failed", extra);
                        close_connection(epoll, fd, ERR_INTERNAL, "TLS handshake failed.");
                    }
                    continue;
                }
            }

            bool should_close = false;
            if (evs & EPOLLIN)
            {
                while (true)
                {
                    char buffer[2048];
                    int bytes_read = SSL_read(conn.ssl.get(), buffer, sizeof(buffer));
                    if (bytes_read > 0)
                    {
                        conn.recv_buffer.append(buffer, static_cast<std::size_t>(bytes_read));

                        while (true)
                        {
                            if (conn.recv_buffer.size() < sizeof(uint32_t))
                                break;
                            uint32_t net_len = 0;
                            std::memcpy(&net_len, conn.recv_buffer.data(), sizeof(uint32_t));
                            uint32_t len = ntohl(net_len);
                            if (len == 0 || len > MAX_FRAME_SIZE)
                            {
                                nlohmann::json extra = {{"fd", fd}, {"error", "invalid_frame_length"}, {"len", len}};
                                Logger::log_event(LogLevel::Warn, "frame_length_error", "Frame length invalid", extra);
                                close_connection(epoll, fd, ERR_BAD_REQUEST, "Invalid frame length.");
                                should_close = true;
                                break;
                            }
                            if (conn.recv_buffer.size() < sizeof(uint32_t) + len)
                                break;

                            std::string payload = conn.recv_buffer.substr(sizeof(uint32_t), len);
                            conn.recv_buffer.erase(0, sizeof(uint32_t) + len);

                            try
                            {
                                json request = json::parse(payload);
                                if (!request.contains("action") || !request["action"].is_string())
                                {
                                    respond_fail(fd, ERR_BAD_REQUEST, "Invalid request format.");
                                    continue;
                                }
                                std::string action = request["action"];
                                if (!requestLimiter.allow(fd))
                                {
                                    metrics.inc_request(action);
                                    metrics.observe_latency(action, std::chrono::microseconds(0));
                                    nlohmann::json extra = {{"fd", fd}, {"action", action}, {"error", ERR_RATE_LIMIT}};
                                    if (!conn.username.empty())
                                        extra["user"] = conn.username;
                                    Logger::log_event(LogLevel::Warn, "rate_limit", "Request rate limit exceeded", extra);
                                    respond_fail(fd, ERR_RATE_LIMIT, "Rate limit exceeded. Please slow down.");
                                    continue;
                                }
                                if ((action == "login" || action == "register") && !authLimiter.allow(fd))
                                {
                                    metrics.inc_request(action);
                                    metrics.observe_latency(action, std::chrono::microseconds(0));
                                    nlohmann::json extra = {{"fd", fd}, {"action", action}, {"error", ERR_AUTH_RATE_LIMIT}};
                                    Logger::log_event(LogLevel::Warn, "rate_limit_auth", "Auth rate limit exceeded", extra);
                                    respond_fail(fd, ERR_AUTH_RATE_LIMIT, "Too many attempts. Please slow down.");
                                    continue;
                                }
                                pool.post([fd, request]()
                                          { process_request(fd, request); });
                            }
                            catch (const std::exception &e)
                            {
                                std::cerr << "❌ JSON parse error from client " << fd << ": " << e.what() << "\n";
                                nlohmann::json extra = {{"fd", fd}, {"error", ERR_JSON_PARSE}, {"detail", e.what()}};
                                Logger::log_event(LogLevel::Warn, "json_parse_error", "Failed to parse JSON request", extra);
                                close_connection(epoll, fd, ERR_JSON_PARSE, "JSON parse error.");
                                should_close = true;
                                break;
                            }
                        }
                        if (should_close)
                            break;
                    }
                    else
                    {
                        int err = SSL_get_error(conn.ssl.get(), bytes_read);
                        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
                        {
                            break;
                        }
                        if (err == SSL_ERROR_ZERO_RETURN)
                        {
                            std::cerr << "🔌 Peer closed TLS for fd " << fd << "\n";
                            nlohmann::json extra = {{"fd", fd}, {"error", "SSL_ERROR_ZERO_RETURN"}};
                            Logger::log_event(LogLevel::Info, "peer_close", "Peer closed TLS", extra);
                            close_connection(epoll, fd, ERR_INTERNAL, "Peer closed connection.");
                        }
                        else
                        {
                            std::cerr << "❌ SSL_read error for fd " << fd << ", err=" << err << "\n";
                            nlohmann::json extra = {{"fd", fd}, {"ssl_error", err}};
                            Logger::log_event(LogLevel::Warn, "ssl_read_error", "SSL_read failed", extra);
                            close_connection(epoll, fd, ERR_INTERNAL, "TLS read error.");
                        }
                        break;
                    }
                }
            }

            if (should_close)
            {
                continue;
            }

            if (evs & EPOLLOUT)
            {
                SendResult res = send_buffered(conn);
                if (res == SendResult::Error)
                {
                    close_connection(epoll, fd, ERR_INTERNAL, "Send error.");
                    continue;
                }
                if (res == SendResult::Ok)
                {
                    epoll_event mod_ev{};
                    mod_ev.events = EPOLLIN | EPOLLET;
                    mod_ev.data.fd = fd;
                    epoll.mod(fd, mod_ev.events);
                }
            }
        }
    }

    return 0;
}
