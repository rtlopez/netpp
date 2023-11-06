#pragma once

#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <unistd.h>

#include <cstring>
#include <string>

#include "Netpp/Exception.h"
#include "Netpp/NetppDebug.h"

namespace Netpp
{

typedef int sock_t;

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

}