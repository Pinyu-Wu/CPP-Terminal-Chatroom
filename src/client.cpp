#include <iostream>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include <cstring>
#include <thread>
#include <cstdlib>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "json.hpp"
#include <termios.h>
#include "ChatManager.hpp"
#include <condition_variable>
#include "FdWrapper.hpp"
#include "Framing.hpp"
#include <cstdint>
#include <atomic>
#include <poll.h>
constexpr int BUFFER_SIZE = 2048;
constexpr std::size_t MAX_FRAME_SIZE = 1 << 20; // 1 MB per message.
using json = nlohmann::json;
std::mutex chat_mutex;
std::condition_variable chat_cv;
std::string chat_target;
bool chat_ready = false;
bool chat_success = false;
bool stop_receiver = false;
std::atomic<bool> in_chat_mode(false);
std::string current_user;
std::mutex chat_target_mutex;
std::mutex history_mutex;
std::condition_variable history_cv;
bool history_ready = false;
std::atomic<bool> shutdown_requested(false);

static bool write_all(SSL *ssl, const char *data, std::size_t len)
{
    std::size_t sent = 0;
    while (sent < len)
    {
        int ret = SSL_write(ssl, data + sent, static_cast<int>(len - sent));
        if (ret <= 0)
        {
            int err = SSL_get_error(ssl, ret);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
                continue;
            return false;
        }
        sent += static_cast<std::size_t>(ret);
    }
    return true;
}

static bool read_line_with_shutdown(std::string &out)
{
    out.clear();
    while (!shutdown_requested.load())
    {
        struct pollfd pfd;
        pfd.fd = STDIN_FILENO;
        pfd.events = POLLIN;
        int ret = poll(&pfd, 1, 200);
        if (ret < 0)
            return false;
        if (ret == 0)
            continue;
        if (pfd.revents & POLLIN)
        {
            if (!std::getline(std::cin, out))
                return false;
            return true;
        }
    }
    return false;
}

static bool send_json(SSL *ssl, const json &j)
{
    std::string payload = j.dump();
    if (payload.size() > MAX_FRAME_SIZE)
    {
        std::cerr << "Payload too large to send.\n";
        return false;
    }
    std::string framed = frame_message(payload);
    return write_all(ssl, framed.data(), framed.size());
}

std::string getPassword(const std::string &prompt = "Password: ")
{
    std::cout << prompt << std::flush;

    termios oldt, newt;
    tcgetattr(STDIN_FILENO, &oldt); // Capture current terminal settings.
    newt = oldt;
    newt.c_lflag &= ~ECHO;                   // Disable echo for password entry.
    tcsetattr(STDIN_FILENO, TCSANOW, &newt); // Apply updated settings.

    std::string password;
    read_line_with_shutdown(password);

    tcsetattr(STDIN_FILENO, TCSANOW, &oldt); // Restore terminal settings.
    std::cout << std::endl;
    return password;
}
void print_main_help()
{
    std::cout << "\n=== Commands ===\n";
    std::cout << "  /listfriends             List your friend(s)\n";
    std::cout << "  /addfriend [Username]    Add [Username] as friend\n";
    std::cout << "  /chat [Username]         Start private chat\n";
    std::cout << "  /help                    Show this help\n";
    std::cout << "  /exit                    Exit chat\n";
    std::cout << "  (Or just type a message!)\n";
}

void print_chat_help()
{
    std::cout << "  /exit        Leave chat\n";
    std::cout << "  /help        Show this help\n";
}

void print_main_prompt()
{
    if (!current_user.empty())
        std::cout << "[" << current_user << "] ";
    std::cout << ">> " << std::flush;
}

void print_chat_prompt()
{
    std::string target;
    {
        std::lock_guard<std::mutex> lock(chat_target_mutex);
        target = chat_target;
    }
    std::cout << "To " << target << " >> " << std::flush;
}

static void print_error(const nlohmann::json &response)
{
    if (response.contains("error"))
    {
        std::cout << "❌ [" << response["error"].get<std::string>() << "] " << response.value("message", "") << "\n";
    }
    else
    {
        std::cout << "❌ " << response.value("message", "") << "\n";
    }
}

void receiver(SSL *ssl)
{
    std::string recv_buffer;
    auto handle_response = [&](const nlohmann::json &response)
    {
        std::string action = response.value("action", "");
        bool printPrompt = true;
        if (response.contains("status") && response["status"] == "fail")
        {
            print_error(response);
        }
        if (action == "listfriends")
        {
            size_t size = response["friendlist"].size();
            std::cout << "You have " << size << " friend(s):" << std::endl;
            for (const auto &friendName : response["friendlist"])
            {
                std::cout << friendName << std::endl;
            }
        }
        else if (action == "normal")
        {
            std::cout << "💬 Server: " << response["message"] << "\n";
        }
        else if (action == "chat_response")
        {
            std::lock_guard<std::mutex> lock(chat_mutex);
            chat_ready = true;
            chat_success = (response["status"] == "success");
            chat_cv.notify_all(); // Wake the input thread.
            std::cout << "💬 [Server action] " << action << ": " << response["message"] << "\n";
        }
        else if (action == "chat_history")
        {
            std::cout << "📜 Chat history with " << response["with"] << ":\n";
            for (const auto &msg : response["history"])
            {
                std::string from = msg["from"];
                std::string content = msg["content"];
                std::string ts = msg["timestamp"];
                std::cout << "[" << ts << "] " << from << ": " << content << "\n";
            }
            {
                std::lock_guard<std::mutex> lock(history_mutex);
                history_ready = true;
            }
            history_cv.notify_all();
            printPrompt = false;
        }
        else if (action == "chat_ack")
        {
            printPrompt = false;
        }
        else if (action == "chat_message")
        {
            std::string from = response["from"];
            std::string content = response["content"];
            std::string time = response["timestamp"];
            std::cout << "\n💬 [" << time << "] " << from << ": " << content << std::endl;
        }
        else if (action == "disconnect")
        {
            std::cout << "🔌 Disconnected: " << response.value("message", "") << "\n";
            exit(EXIT_FAILURE);
        }
        else
        {
            std::cout << "💬 [Server action] " << action << ": " << response["message"] << "\n";
        }
        if (printPrompt)
        {
            if (in_chat_mode)
            {
                std::cout << "\n";
                print_chat_prompt();
            }
            else
            {
                print_main_prompt();
            }
        }
    };

    while (true)
    {
        char buffer[BUFFER_SIZE] = {0};
        int bytes_received = SSL_read(ssl, buffer, sizeof(buffer));
        if (bytes_received <= 0)
        {
            if (!stop_receiver)
            {
                std::cerr << "Server disconnected or JSON error. Exiting...\n";
                shutdown_requested = true;
            }
            return;
        }
        recv_buffer.append(buffer, static_cast<std::size_t>(bytes_received));

        while (true)
        {
            if (recv_buffer.size() < sizeof(uint32_t))
                break;

            uint32_t net_len = 0;
            std::memcpy(&net_len, recv_buffer.data(), sizeof(uint32_t));
            uint32_t len = ntohl(net_len);
            if (len == 0 || len > MAX_FRAME_SIZE)
            {
                std::cerr << "Invalid frame length. Exiting...\n";
                exit(EXIT_FAILURE);
            }
            if (recv_buffer.size() < sizeof(uint32_t) + len)
                break;

            std::string payload = recv_buffer.substr(sizeof(uint32_t), len);
            recv_buffer.erase(0, sizeof(uint32_t) + len);

            nlohmann::json response;
            try
            {
                response = nlohmann::json::parse(payload);
            }
            catch (const std::exception &)
            {
                std::cerr << "Server disconnected or JSON error. Exiting...\n";
                exit(EXIT_FAILURE);
            }

            handle_response(response);
        }
    }
}

void enter_chat_mode(std::string friendName, SSL *ssl)
{
    in_chat_mode = true;

    std::cout << "\n=== Chat with '" << friendName << "' ===\n";
    print_chat_help();

    {
        std::lock_guard<std::mutex> lock(history_mutex);
        history_ready = false;
    }

    // Request chat history before entering the loop.
    json history_request;
    history_request["action"] = "get_history";
    history_request["target"] = friendName;
    send_json(ssl, history_request);

    // Wait for the receiver to print history.
    {
        std::unique_lock<std::mutex> lock(history_mutex);
        history_cv.wait_for(lock, std::chrono::seconds(2), []
                            { return history_ready; });
    }

    std::string msg;
    while (true)
    {
        print_chat_prompt();
        if (!read_line_with_shutdown(msg))
            break;
        if (msg == "/exit")
            break;
        if (msg == "/help")
        {
            print_chat_help();
            continue;
        }

        json j;
        j["action"] = "chat_message";
        j["target"] = friendName;
        j["content"] = msg;
        send_json(ssl, j);
    }

    in_chat_mode = false;
    return;
}

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        std::cerr << "Usage: " << argv[0] << " <SERVER_ADDRESS> <PORT>\n";
        return EXIT_FAILURE;
    }

    const char *server_host = argv[1];
    const char *port_str = argv[2];

    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;     // Allow IPv4 or IPv6.
    hints.ai_socktype = SOCK_STREAM; // TCP stream socket.
    hints.ai_protocol = IPPROTO_TCP;

    addrinfo *result = nullptr;
    int gai_rc = getaddrinfo(server_host, port_str, &hints, &result);
    if (gai_rc != 0)
    {
        std::cerr << "Invalid address / Address not supported: " << gai_strerror(gai_rc) << "\n";
        return EXIT_FAILURE;
    }

    Fd sock;
    for (addrinfo *rp = result; rp != nullptr; rp = rp->ai_next)
    {
        int fd = ::socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0)
            continue;
        if (::connect(fd, rp->ai_addr, rp->ai_addrlen) == 0)
        {
            sock = Fd(fd);
            break;
        }
        ::close(fd);
    }
    freeaddrinfo(result);

    if (!sock.valid())
    {
        perror("Connection Failed");
        return EXIT_FAILURE;
    }

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    SslCtxPtr ctx(SSL_CTX_new(TLS_client_method()));
    if (!ctx)
    {
        std::cerr << "Failed to create SSL_CTX\n";
        return EXIT_FAILURE;
    }

    if (SSL_CTX_load_verify_locations(ctx.get(), "config/cert.pem", nullptr) == 1)
    {
        SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_PEER, nullptr);
    }
    else
    {
        // Dev-only fallback: skip verification if cert not provided locally.
        std::cerr << "⚠️  Could not load config/cert.pem, skipping verification (development only).\n";
        SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_NONE, nullptr);
    }

    SslPtr ssl(SSL_new(ctx.get()));
    if (!ssl)
    {
        std::cerr << "Failed to create SSL object\n";
        return EXIT_FAILURE;
    }

    SSL_set_fd(ssl.get(), sock.get());
    if (SSL_connect(ssl.get()) <= 0)
    {
        ERR_print_errors_fp(stderr);
        return EXIT_FAILURE;
    }

    std::string input;
    // Login/registration phase.
    bool loggin = false;
    std::string recv_buffer;

    while (!loggin)
    {
        std::string choice;
        std::cout << "== Welcome to Chat ==\n";
        std::cout << "1. Login\n2. Register\n>> " << std::flush;
        if (!read_line_with_shutdown(choice))
            return 1;

        if (choice != "1" && choice != "2")
        {
            std::cout << "Wrong action, please try again!\n";
            continue;
        }
        std::string action = (choice == "1") ? "login" : "register";
        std::string username, password;

        std::cout << "Username: " << std::flush;
        if (!read_line_with_shutdown(username))
            return 1;
        password = getPassword();
        json request;
        request["action"] = action;
        request["username"] = username;
        request["password"] = password; // Plaintext over TLS.

        send_json(ssl.get(), request);

        json response;
        bool got_response = false;
        while (!got_response)
        {
            char buffer[BUFFER_SIZE] = {0};
            int bytes = SSL_read(ssl.get(), buffer, sizeof(buffer));
            if (bytes <= 0)
            {
                std::cerr << "Server disconnected.\n";
                return 1;
            }
            recv_buffer.append(buffer, static_cast<std::size_t>(bytes));
            if (recv_buffer.size() < sizeof(uint32_t))
                continue;
            uint32_t net_len = 0;
            std::memcpy(&net_len, recv_buffer.data(), sizeof(uint32_t));
            uint32_t len = ntohl(net_len);
            if (len == 0 || len > MAX_FRAME_SIZE)
            {
                std::cerr << "Invalid frame length.\n";
                return 1;
            }
            if (recv_buffer.size() < sizeof(uint32_t) + len)
                continue;
            std::string payload = recv_buffer.substr(sizeof(uint32_t), len);
            recv_buffer.erase(0, sizeof(uint32_t) + len);

            try
            {
                response = json::parse(payload);
                got_response = true;
            }
            catch (const std::exception &)
            {
                std::cerr << "Server disconnected.\n";
                return 1;
            }
        }

        if (response["status"] == "success")
        {
            std::cout << "✅ " << action << " successful! You are logged in.\n";
            current_user = username;
            loggin = true;
            print_main_help();
        }
        else
        {
            print_error(response);
        }
    }

    // Background receiver thread.
    std::thread t(receiver, ssl.get());

    while (true)
    {
        print_main_prompt();
        if (!read_line_with_shutdown(input))
            break;
        if (input == "/exit")
            break;

        json j;
        if (input.rfind("/addfriend ", 0) == 0)
        {
            std::string friendName = input.substr(11);
            j["action"] = "addfriend";
            j["target"] = friendName;
            send_json(ssl.get(), j);
        }
        else if (input == "/listfriends")
        {
            j["action"] = "listfriends";
            send_json(ssl.get(), j);
        }
        else if (input.rfind("/chat ", 0) == 0)
        {
            {
                std::lock_guard<std::mutex> lock(chat_mutex);
                chat_ready = false;
            }
            std::string name = input.substr(6);
            name.erase(0, name.find_first_not_of(' '));
            name.erase(name.find_last_not_of(' ') + 1);
            {
                std::lock_guard<std::mutex> lock(chat_target_mutex);
                chat_target = name;
            }
            json j;
            j["action"] = "chat_request";
            j["target"] = name;
            send_json(ssl.get(), j);

            // Wait up to 10 seconds for the chat response.
            {
                std::unique_lock<std::mutex> lock(chat_mutex);
                if (chat_cv.wait_for(lock, std::chrono::seconds(10), []
                                     { return chat_ready; }))
                {
                    if (chat_success)
                    {
                        std::string target;
                        {
                            std::lock_guard<std::mutex> target_lock(chat_target_mutex);
                            target = chat_target;
                        }
                        lock.unlock();
                        std::cout << "✅ Entering chat with " << target << "\n";
                        enter_chat_mode(target, ssl.get());
                    }
                    else
                    {
                        std::cout << "❌ Cannot chat with this user.\n";
                    }
                }
                else
                {
                    std::cout << "⏳ Timeout waiting for chat result\n";
                }
            }
        }
        else if (input == "/help")
        {
            print_main_help();
        }
        else
        {
            // Regular message to the server.
            j["action"] = "normal";
            j["message"] = input;
            send_json(ssl.get(), j);
        }
    }

    stop_receiver = true;
    if (sock.valid())
    {
        ::shutdown(sock.get(), SHUT_RDWR); // wake receiver out of SSL_read
        sock.reset();                      // close immediately so SSL_read unblocks
    }
    if (t.joinable())
    {
        t.join();
    }
    SSL_shutdown(ssl.get());
    return 0;
}
