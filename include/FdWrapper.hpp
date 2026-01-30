#pragma once

#include <sys/epoll.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <memory>

class Fd
{
public:
    Fd() = default;
    explicit Fd(int fd) : fd_(fd) {}
    ~Fd() { reset(); }

    Fd(const Fd &) = delete;
    Fd &operator=(const Fd &) = delete;

    Fd(Fd &&other) noexcept : fd_(other.fd_) { other.fd_ = -1; }
    Fd &operator=(Fd &&other) noexcept
    {
        if (this != &other)
        {
            reset();
            fd_ = other.fd_;
            other.fd_ = -1;
        }
        return *this;
    }

    int get() const { return fd_; }
    bool valid() const { return fd_ != -1; }

    int release()
    {
        int tmp = fd_;
        fd_ = -1;
        return tmp;
    }

    void reset(int new_fd = -1)
    {
        if (fd_ != -1)
        {
            ::close(fd_);
        }
        fd_ = new_fd;
    }

private:
    int fd_{-1};
};

class Epoll
{
public:
    Epoll() : epfd_(::epoll_create1(0)) {}
    explicit Epoll(int epfd) : epfd_(epfd) {}

    int get() const { return epfd_.get(); }
    bool valid() const { return epfd_.valid(); }

    bool add(int fd, uint32_t events) { return ctl(EPOLL_CTL_ADD, fd, events); }
    bool mod(int fd, uint32_t events) { return ctl(EPOLL_CTL_MOD, fd, events); }
    bool del(int fd) { return ctl(EPOLL_CTL_DEL, fd, 0); }

private:
    bool ctl(int op, int fd, uint32_t events)
    {
        if (!epfd_.valid())
            return false;
        epoll_event ev{};
        ev.events = events;
        ev.data.fd = fd;
        return ::epoll_ctl(epfd_.get(), op, fd, &ev) == 0;
    }

    Fd epfd_;
};

struct SslDeleter
{
    void operator()(SSL *ssl) const
    {
        if (ssl)
        {
            SSL_free(ssl);
        }
    }
};

struct SslCtxDeleter
{
    void operator()(SSL_CTX *ctx) const
    {
        if (ctx)
        {
            SSL_CTX_free(ctx);
        }
    }
};

using SslPtr = std::unique_ptr<SSL, SslDeleter>;
using SslCtxPtr = std::unique_ptr<SSL_CTX, SslCtxDeleter>;
