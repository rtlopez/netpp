#pragma once

extern "C" {
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>
#include <unistd.h>
}

#include <cstring>
#include <cerrno>
#include <functional>
#include <map>
#include <stdexcept>
#include <string>

#if 1
namespace {

template<typename T>
void debug(T last)
{
    std::cout << last << "\n";
}

template<typename T, typename... Args>
void debug(T first, Args... args)
{
    std::cout << first << " ";
    debug(args...);
}

}
#else
#define debug(...)
#endif

namespace Netpp
{

typedef int sock_t;

class ErrnoException: public std::runtime_error
{
public:
    ErrnoException(int erno, const std::string& msg): std::runtime_error(msg), _msg(msg), _errno(erno)
    {
        _msg += ": (";
        _msg += std::to_string(errNo());
        _msg += ") ";
        _msg += errStr();
    }
    int errNo() const
    {
        return _errno;
    }
    const char * errStr() const
    {
        return std::strerror(_errno);
    }
    virtual const char * what() const noexcept override
    {
        return _msg.c_str();
    }
private:
    std::string _msg;
    int _errno;
};

class SocketException: public ErrnoException
{
public:
    SocketException(int eno, const std::string& msg): ErrnoException(eno, msg) {}
};

class EpollException: public ErrnoException
{
public:
    EpollException(int eno, const std::string& msg): ErrnoException(eno, msg) {}
};

class Socket
{
public:
    static sock_t create(int domain, int type, int protocol)
    {
        sock_t fd = ::socket(domain, type, protocol);

        debug("Socket::create", fd);

        if (fd < 0) throw SocketException(errno, "socket() failed");

        return fd;
    }

    static int bind(sock_t fd, const char * bind_addr, uint16_t bind_port)
    {
        sockaddr_in addr;
        socklen_t addr_len = sizeof(addr);
        std::memset(&addr, 0, addr_len);
        addr.sin_family = AF_INET;
        addr.sin_port = htons(bind_port);
        addr.sin_addr.s_addr = inet_addr(bind_addr);

        int ret = ::bind(fd, (sockaddr*)&addr, addr_len);

        debug("Socket::bind", ret);

        if (ret < 0) throw SocketException(errno, "bind() failed");

        return ret;
    }

    static int listen(sock_t fd, int size)
    {
        int ret = ::listen(fd, size);

        debug("Socket::listen", ret);

        if (ret < 0) throw SocketException(errno, "listen() failed");

        return ret;
    }

    static int accept(sock_t fd, sockaddr_in& addr)
    {
        socklen_t addr_len = sizeof(addr);
        std::memset(&addr, 0, sizeof(addr));

        sock_t afd = ::accept(fd, (sockaddr *)&addr, &addr_len);

        debug("Socket::accept", afd);

        if (errno == EAGAIN) return 0;
        
        if (afd < 0) throw SocketException(errno, "accept() failed");

        return afd;
    }

    static const std::string getpeername(sock_t fd)
    {
        sockaddr_in addr;
        socklen_t addr_size = sizeof(sockaddr_in);
        ::getpeername(fd, (sockaddr *)&addr, &addr_size);
        uint16_t port = addr.sin_port;
        in_addr_t * saddr = &addr.sin_addr.s_addr;
        char ip_str[INET_ADDRSTRLEN];
        const char * clientip = ::inet_ntop(AF_INET, saddr, ip_str, INET_ADDRSTRLEN);
        return std::string{clientip} + std::string{":"} + std::to_string(port);
    }
};

class EpollHandler
{
public:
    virtual void handle(sock_t s, uint32_t events) = 0;
};

class Epoll
{
public:
    Epoll(): _fd(-1), _running(true), _timeout(10000)
    {
        init();
    }

    ~Epoll()
    {
        debug("Epoll::close", _fd);
        if(_fd >= 0) ::close(_fd);
    }

    void init()
    {
        sock_t fd = ::epoll_create1(0);
        
        debug("Epoll::init", fd);

        if (fd < 0) throw EpollException(errno, "epoll_create1() failed");

        _fd = fd;
    }

    void add(sock_t fd, uint32_t events, EpollHandler* handler)
    {
        if(!_fd) throw EpollException(-1, "Epoll not initialized");

        debug("Epoll::add", fd, events);

        epoll_event event = {0, {0}};

        event.events = events;
        event.data.fd = fd;

        if (epoll_ctl(_fd, EPOLL_CTL_ADD, fd, &event) < 0)
        {
            throw EpollException(errno, "epoll_ctl(EPOLL_CTL_ADD) failed");
        }

        _handlers[fd] = handler;
    }

    void del(sock_t fd)
    {
        if(!_fd) throw EpollException(errno, "Epoll not initialized");

        debug("Epoll::del", fd);

        if (epoll_ctl(_fd, EPOLL_CTL_DEL, fd, NULL) < 0)
        {
            throw EpollException(errno, "epoll_ctl(EPOLL_CTL_DEL) failed");
        }

        _handlers.erase(fd);
    }

    void run()
    {
        if(!_fd) throw EpollException(errno, "Epoll not initialized");

        while (_running)
        {
            int ret = ::epoll_wait(_fd, _events, MAX_EVENTS, _timeout);
            if (ret == -1)
            {
                debug("Epoll::run", "error", ret, errno);
                if (errno == EINTR) continue; // interrupted, try again
                throw EpollException(errno, "epoll_wait() failed");
            }

            if (ret == 0)
            {
                // `epoll_wait` reached its timeout
                debug("Epoll::run", "timeout", ret);
                continue;
            }

            for (int i = 0; i < ret; i++)
            {
                handle(_events[i]);
            }
        }
    }

    void handle(const epoll_event& ev)
    {
        debug("Epoll::run", "handle", ev.data.fd, ev.events);
        EpollHandler* handler = _handlers[ev.data.fd];
        handler->handle(ev.data.fd, ev.events);
    }

    void stop()
    {
        _running = false;
    }

private:
    static const size_t MAX_EVENTS = 32;
    sock_t _fd;
    bool _running;
    int _timeout;
    epoll_event _events[MAX_EVENTS];
    std::map<sock_t, EpollHandler*> _handlers;
};

class TcpServer: public EpollHandler
{
public:
    enum Status {
        OK,
        ERROR,
        CLOSE,
    };
    typedef std::function<Status(sock_t)> callback_t;

    TcpServer(const char * addr, uint16_t port, Epoll& epoll):
        _addr(addr), _port(port), _epoll(epoll), _s(-1)
    {
        init();
    }
    virtual ~TcpServer()
    {
        debug("TcpServer::close", _s);
        if(_s >= 0) ::close(_s);
    }

    void onConn(callback_t cb) { _onConn = cb; }
    void onRecv(callback_t cb) { _onRecv = cb; }
    void onClose(callback_t cb) { _onClose = cb; }

    void init()
    {
        sock_t s = Socket::create(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);
        debug("TcpServer::init", s);
        Socket::bind(s, _addr, _port);
        Socket::listen(s, 100);
        _s = s;
        _epoll.add(s, EPOLLIN | EPOLLPRI, this);
    }

    virtual void handle(sock_t s, uint32_t events) override
    {
        if (s == _s)
        {
            try {
                debug("TcpServer::handle", "accept", s, events);
                sockaddr_in addr;
                sock_t as = Socket::accept(_s, addr);
                _epoll.add(as, EPOLLIN | EPOLLPRI, this);
                if(_onConn) _onConn(as);
            } catch(...) {
                debug("TcpServer::handle", "accept", "exception", s, events);
            }
        }
        else if (events & (EPOLLERR | EPOLLHUP))
        {
            try {
                debug("TcpServer::handle", "close", s, events);
                close(s);
            } catch(...) {
                debug("TcpServer::handle", "close", "exception", s, events);
            }
        }
        else
        {
            try {
                debug("TcpServer::handle", "recv", s, events);
                if(_onRecv)
                {
                    Status status = _onRecv(s);
                    if(status == CLOSE || status == ERROR)
                    {
                        close(s);
                    }
                }
            } catch(...) {
                debug("TcpServer::handle", "recv", "exception", s, events);
                close(s);
            }
        }
    }

    sock_t native() const
    {
        return _s;
    }
private:
    void close(sock_t s)
    {
        debug("TcpServer::close", s);
        _epoll.del(s);
        if(_onClose) _onClose(s);
        ::close(s);
    }

    const char * _addr;
    uint16_t _port;
    Epoll& _epoll;
    callback_t _onRecv;
    callback_t _onConn;
    callback_t _onClose;
    sock_t _s;
};

}
