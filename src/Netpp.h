#pragma once

extern "C" {
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>
#include <unistd.h>
}

#include <algorithm>
#include <charconv>
#include <cstring>
#include <cerrno>
#include <functional>
#include <map>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <set>
#include <tuple>

#if 0
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

class EventLoopException: public ErrnoException
{
public:
    EventLoopException(int eno, const std::string& msg): ErrnoException(eno, msg) {}
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
        const int enable = 1;
        if (::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0)
        {
            throw SocketException(errno, "setsockopt(SO_REUSEADDR) failed");
        }
        if (::setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &enable, sizeof(int)) < 0)
        {
            throw SocketException(errno, "setsockopt(SO_REUSEPORT) failed");
        }

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

        debug("Socket::accept", fd, afd, errno);

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

class EventLoopHandler
{
public:
    virtual void handle(sock_t s, uint32_t events) = 0;
};

class EventLoop
{
public:
    virtual void add(sock_t fd, uint32_t events, EventLoopHandler* handler) = 0;
    virtual void del(sock_t fd) = 0;
    virtual void run() = 0;
};

class EventLoopEpoll: public EventLoop
{
public:
    EventLoopEpoll(): _fd(-1), _running(true), _timeout(10000)
    {
        sock_t fd = ::epoll_create1(0);
        
        debug("EventLoopEpoll::init", fd);

        if (fd < 0) throw EventLoopException(errno, "epoll_create1() failed");

        _fd = fd;
    }

    virtual ~EventLoopEpoll()
    {
        debug("EventLoopEpoll::close", _fd);
        if(_fd >= 0) ::close(_fd);
    }

    virtual void add(sock_t fd, uint32_t events, EventLoopHandler* handler) override
    {
        if(!_fd) throw EventLoopException(-1, "EventLoopEpoll not initialized");

        debug("EventLoopEpoll::add", fd, events);

        epoll_event event = {events, {.fd = fd}};

        if (epoll_ctl(_fd, EPOLL_CTL_ADD, fd, &event) < 0)
        {
            throw EventLoopException(errno, "epoll_ctl(EPOLL_CTL_ADD) failed");
        }

        _handlers[fd] = handler;
    }

    virtual void del(sock_t fd) override
    {
        if(!_fd) throw EventLoopException(errno, "EventLoopEpoll not initialized");

        debug("EventLoopEpoll::del", fd);

        if (epoll_ctl(_fd, EPOLL_CTL_DEL, fd, NULL) < 0)
        {
            throw EventLoopException(errno, "epoll_ctl(EPOLL_CTL_DEL) failed");
        }

        _handlers.erase(fd);
    }

    virtual void run() override
    {
        if(!_fd) throw EventLoopException(errno, "EventLoopEpoll not initialized");

        while (_running)
        {
            int ret = ::epoll_wait(_fd, _events, MAX_EVENTS, _timeout);
            if (ret == -1)
            {
                debug("EventLoopEpoll::run", "error", ret, errno);
                if (errno == EINTR) continue; // interrupted, try again
                throw EventLoopException(errno, "epoll_wait() failed");
            }

            if (ret == 0)
            {
                // `epoll_wait` reached its timeout
                debug("EventLoopEpoll::run", "timeout", ret);
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
        debug("EventLoopEpoll::run", "handle", ev.data.fd, ev.events);
        EventLoopHandler* handler = _handlers[ev.data.fd];
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
    std::map<sock_t, EventLoopHandler*> _handlers;
};


class Protocol
{
public:
    enum Status {
        OK,
        ERROR,
        CLOSE,
    };
    virtual Status onConnect(sock_t s) = 0;
    virtual Status onReceive(sock_t s) = 0;
    virtual Status onDisconnect(sock_t s) = 0;
};

class TcpServer: public EventLoopHandler
{
public:
    TcpServer(const char * addr, uint16_t port, EventLoop* loop, Protocol* protocol):
        _addr(addr), _port(port), _loop(loop), _protocol(protocol), _s(-1)
    {
        sock_t s = Socket::create(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);
        debug("TcpServer::init", s);
        Socket::bind(s, _addr, _port);
        Socket::listen(s, 100);
        _s = s;
        _loop->add(s, EPOLLIN | EPOLLPRI, this);
    }
    virtual ~TcpServer()
    {
        debug("TcpServer::close", _s);
        if(_s >= 0) ::close(_s);
    }

    virtual void handle(sock_t s, uint32_t events) override
    {
        if (s == _s)
        {
            try {
                debug("TcpServer::handle", "accept", s, events);
                sockaddr_in addr;
                sock_t as = Socket::accept(_s, addr);
                if(as <= 0) return;
                _loop->add(as, EPOLLIN | EPOLLPRI, this);
                Protocol::Status status = _protocol->onConnect(as);
                if(status == Protocol::CLOSE || status == Protocol::ERROR)
                {
                    close(as);
                }
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
                Protocol::Status status = _protocol->onReceive(s);
                if(status == Protocol::CLOSE || status == Protocol::ERROR)
                {
                    close(s);
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
        _loop->del(s);
        _protocol->onDisconnect(s);
        ::close(s);
    }

    const char * _addr;
    uint16_t _port;
    EventLoop* _loop;
    Protocol* _protocol;
    sock_t _s;
};

class EchoProtocol: public Protocol
{
public:
    virtual ~EchoProtocol() {}

    virtual Status onConnect(sock_t s)
    {
        std::string ip = std::move(Socket::getpeername(s));
        std::cout << "[ECHO] conn accept: " << ip << "\n";
        return Protocol::OK;
    }

    virtual Status onDisconnect(sock_t s)
    {
        std::string ip = std::move(Socket::getpeername(s));
        std::cout << "[ECHO] conn close: " << ip << "\n";
        return Protocol::OK;
    }

    virtual Status onReceive(sock_t s)
    {
        char buff[1024];
        ssize_t len = ::recv(s, buff, sizeof(buff), 0);

        if(len < 0)
        {
            std::cout << "[ECHO] data error: " << len << " " << errno << "\n";
            if (errno == EAGAIN || errno == EWOULDBLOCK) return Protocol::OK;
            return Protocol::ERROR;
        }

        if(len == 0)
        {
            std::cout << "[ECHO] empty data\n";
            return Protocol::CLOSE;
        }

        ssize_t slen = ::send(s, buff, len, 0);

        if(slen != len)
        {
            std::cout << "[ECHO] FIXME: not all data resent\n";
        }

        buff[len] = '\0';
        if(buff[len - 1] == '\n') buff[len - 1] = '\0';
        if(buff[len - 2] == '\r') buff[len - 2] = '\0';

        std::cout << "[ECHO] new data: " << buff << "\n";

        return Protocol::OK;
    }
};

class ChatProtocol: public Protocol
{
public:
    virtual ~ChatProtocol() {}

    virtual Status onConnect(sock_t s)
    {
        _clients.insert(s);

        const char buff[] = "Welcome to the chat room\n";
        ssize_t len = sizeof(buff) - 1;
        ssize_t slen = send(s, buff, len, 0);
        if(slen != len)
        {
            std::cout << "[CHAT] FIXME: not all data resent\n";
        }

        std::string ip = std::move(Socket::getpeername(s));
        std::cout << "[CHAT] " << ip << " joined room\n";

        return Protocol::OK;
    }

    virtual Status onDisconnect(sock_t s)
    {
        _clients.erase(s);

        std::string ip = std::move(Socket::getpeername(s));
        std::cout << "[CHAT] " << ip << " left room\n";

        return Protocol::OK;
    }

    virtual Status onReceive(sock_t s)
    {
        char buff[1024];
        ssize_t len = ::recv(s, buff, sizeof(buff), 0);

        if(len < 0)
        {
            std::cout << "[CHAT] data error: " << len << " " << errno << "\n";
            if (errno == EAGAIN || errno == EWOULDBLOCK) return Protocol::OK;
            return Protocol::ERROR;
        }

        if(len == 0)
        {
            std::cout << "[CHAT] empty data\n";
            return Protocol::CLOSE;
        }

        for(sock_t c: _clients)
        {
            if(c == s) continue;
            ssize_t slen = ::send(c, buff, len, 0);
            if(slen != len)
            {
                std::cout << "[CHAT] FIXME: not all data resent\n";
            }
        }

        buff[len] = '\0';
        if(buff[len - 1] == '\n') buff[len - 1] = '\0';
        if(buff[len - 2] == '\r') buff[len - 2] = '\0';

        std::cout << "[CHAT] new data: " << buff << "\n";

        return Protocol::OK;
    }
private:
    std::set<sock_t> _clients;
};

class HttpRequest
{
    enum State {
        PARSE_METHOD,
        PARSE_PATH,
        PARSE_VERSION,
        PARSE_HEADERS,
        PARSE_DONE,
    };
public:
    std::string method;
    std::string path;
    std::string version;
    std::map<std::string, std::string> headers;
    std::vector<char> header;
    std::vector<char> body;

    std::tuple<bool, bool, size_t> receive(const char * c, size_t len)
    {
        if(!len)
        {
            return {_headerReceived, _headerParsed, body.size()};
        }
        if(!_headerReceived)
        {
            std::string s{c, len};
            size_t pos = s.find("\r\n\r\n");
            if(pos == std::string::npos)
            {
                std::copy(c, c + len, std::back_inserter(header));
            }
            else
            {
                std::copy(c, c + pos + 4, std::back_inserter(header));
                _headerReceived = true;
                if(pos + 4 < len)
                {
                    std::copy(c + pos + 4, c + len, std::back_inserter(body));
                }
                parse();
            }
        }
        else
        {
            std::copy(c, c + len, std::back_inserter(body));
        }
        return {_headerReceived, _headerParsed, body.size()};
    }

    bool parse()
    {
        State state = PARSE_METHOD;
        std::string s{header.begin(), header.end()};
        size_t from = 0;
        while(true)
        {
            switch(state)
            {
                case PARSE_METHOD: {
                    size_t to = s.find(' ', from);
                    if(to == std::string::npos) return false;
                    method = s.substr(from, to - from);
                    from = to + 1;
                    state = PARSE_PATH;
                    break;
                }
                case PARSE_PATH: {
                    size_t to = s.find(' ', from);
                    if(to == std::string::npos) return false;
                    path = s.substr(from, to - from);
                    from = to + (1 + 4 + 1); // skip " HTTP/"
                    state = PARSE_VERSION;
                    break;
                }
                case PARSE_VERSION: {
                    size_t to = s.find("\r\n", from);
                    if(to == std::string::npos) return false;
                    version = s.substr(from, to - from);
                    from = to + 2;
                    state = PARSE_HEADERS;
                    break;
                }
                case PARSE_HEADERS: {
                    size_t to = s.find("\r\n", from);
                    if(to == std::string::npos) return false;
                    if(from == to)
                    {
                        state = PARSE_DONE;
                        _headerParsed = true;
                        break;
                    }
                    std::string line = s.substr(from, to - from);
                    size_t cto = line.find(':');
                    if(cto == std::string::npos) return false;
                    std::string key = trim(line.substr(0, cto));
                    std::string val = trim(line.substr(cto + 1));
                    std::transform(key.begin(), key.end(), key.begin(), ::tolower);
                    headers[key] = val;
                    from = to + 2;
                    break;
                }
                case PARSE_DONE:
                    return true;
                    break;
            }
        }
        return false;
    }

    const std::string str() const
    {
        std::ostringstream ss;

        ss << method << ' ' << path << " HTTP/" << version << "\r\n";
        for(auto [key, val]: headers)
        {
            ss << key << ": " << val << "\r\n";
        }
        ss << "\r\n";

        return ss.str();
    }

    bool headerReceived() const
    {
        return _headerReceived;
    }

    bool headerParsed() const
    {
        return _headerParsed;
    }
private:
    bool _headerReceived = false;
    bool _headerParsed = false;

    static std::string trim(std::string str)
    {
        str.erase(str.find_last_not_of(' ') + 1);       //suffixing spaces
        str.erase(0, str.find_first_not_of(' '));       //prefixing spaces
        return str;
    }
};

class HttpResponse
{
public:
    std::string version = "0.9";
    int status = 200;
    std::map<std::string, std::string> headers;

    const std::string str() const
    {
        std::ostringstream ss;

        ss << "HTTP/" << version << ' ' << status << ' ' << codeToMessage(status) << "\r\n";
        for(auto [key, val]: headers)
        {
            ss << key << ": " << val << "\r\n";
        }
        ss << "\r\n";

        return ss.str();
    }

    static const char * codeToMessage(int code)
    {
        switch(code)
        {
            case 100: return "Continue";

            case 200: return "OK";
            case 201: return "Created";
            case 204: return "No Content";
            case 301: return "Moved Permanently";
            case 302: return "Found";
            case 304: return "Not Modified";

            case 400: return "Bad Request";
            case 401: return "Unauthorized";
            case 403: return "Forbidden";
            case 404: return "Not Found";
            case 405: return "Method Not Allowed";
            case 406: return "Not Acceptable";
            case 408: return "Request Timeout";
            case 410: return "Gone";
            case 411: return "Length Required";
            case 413: return "Payload Too Large";
            case 414: return "URI Too Long";
            case 415: return "Unsupported Media Type";
            case 429: return "Too Many Requests";

            case 500: return "Internal Server Error";
            case 501: return "Not Implemented";
            case 502: return "Bad Gateway";
            case 503: return "Service Unavailable";
            case 504: return "Gateway Timeout";
        }
        return "Unknown";
    }
};

class HttpProtocol: public Protocol
{
public:
    virtual ~HttpProtocol() {}

    virtual Status onConnect(sock_t s)
    {
        _requests[s] = std::make_shared<HttpRequest>();
        std::string ip = std::move(Socket::getpeername(s));
        std::cout << "[HTTP] " << ip << " connected\n";
        return Protocol::OK;
    }

    virtual Status onDisconnect(sock_t s)
    {
        _requests.erase(s);
        std::string ip = std::move(Socket::getpeername(s));
        std::cout << "[HTTP] " << ip << " disconnected\n";
        return Protocol::OK;
    }

    virtual Status onReceive(sock_t s)
    {
        char buff[1024];
        ssize_t len = ::recv(s, buff, sizeof(buff), 0);

        if(len < 0)
        {
            std::cout << "[HTTP] data error: " << len << " " << errno << "\n";
            if (errno == EAGAIN || errno == EWOULDBLOCK) return Protocol::OK;
            return Protocol::ERROR;
        }

        if(len == 0)
        {
            return Protocol::CLOSE;
        }

        std::shared_ptr<HttpRequest> req = _requests[s];
        auto [headerReceived, headerParsed, bodySize] = req->receive(buff, len);

        if(headerReceived)
        {
            if(!headerParsed)
            {
                std::cout << "[HTTP] Malformed request\n";
                std::cout << "[HTTP] " << std::string{req->header.begin(), req->header.end()} << "\n";
                sendHeaders(s, req, 400, 0);
                return Protocol::CLOSE;
            }
            else
            {
                size_t expectedSize = 0;
                auto it = req->headers.find("content-length");
                if(it != req->headers.end())
                {
                    std::string s = it->second;
                    std::from_chars(s.data(), s.data() + s.size(), expectedSize);
                }

                if(bodySize == expectedSize)
                {
                    const char * content = "<html>\n<head></head>\n<body></body>\n</html>\n";
                    size_t len = strlen(content);
                    sendHeaders(s, req, 200, len);
                    sendBody(s, content, len);
                }
            }
        }

        return Protocol::OK;
    }

private:
    void sendHeaders(sock_t s, std::shared_ptr<HttpRequest> req, int status, size_t len)
    {
        HttpResponse res;
        res.status = status;
        res.version = req->version;
        res.headers["Content-Type"] = "text/html";
        res.headers["Content-Length"] = std::to_string(len);
        const std::string headers = res.str();
        ssize_t ret = ::send(s, headers.c_str(), headers.size(), 0);
        std::cout << "[HTTP] sent headers " << ret << ' ' << errno << ' ' << strerror(errno) << "\n";
    }

    void sendBody(sock_t s, const char * content, size_t len)
    {
        ssize_t ret = ::send(s, content, len, 0);
        std::cout << "[HTTP] sent body " << ret << ' ' << errno << ' ' << strerror(errno) << "\n";
    }

    std::map<sock_t, std::shared_ptr<HttpRequest>> _requests;
};

}
