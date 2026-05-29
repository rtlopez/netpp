#pragma once

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <unistd.h>

#include <cstring>
#include <string>

#include "Netpp/Exception.h"
#include "Netpp/NetppDebug.h"

namespace Netpp
{

using sock_t = int;

class Socket
{
public:
  static sock_t create(int domain, int type, int protocol)
  {
    sock_t fd = ::socket(domain, type, protocol);
    auto err = errno;
    debug("Socket::create", domain, type, protocol, fd, err, ::strerror(err));

    if (fd < 0)
    {
      throw SocketException(err, "socket() failed");
    }

    return fd;
  }

  static ssize_t send(sock_t fd, const void *buf, size_t len, int flags)
  {
    return ::send(fd, buf, len, flags);
  }

  static ssize_t recv(sock_t fd, void *buf, size_t len, int flags)
  {
    return ::recv(fd, buf, len, flags);
  }

  static int bind(sock_t fd, const char *bind_addr, uint16_t bind_port)
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

    int ret = ::bind(fd, (sockaddr *)&addr, addr_len);
    int err = errno;
    debug("Socket::bind", fd, ret, err, ::strerror(err));

    if (ret < 0)
    {
      throw SocketException(err, "bind() failed");
    }

    return ret;
  }

  static int listen(sock_t fd, int size)
  {
    int ret = ::listen(fd, size);
    int err = errno;
    debug("Socket::listen", fd, ret, err, ::strerror(err));

    if (ret < 0)
    {
      throw SocketException(err, "listen() failed");
    }

    return ret;
  }

  static int accept(sock_t fd, sockaddr_in &addr)
  {
    socklen_t addr_len = sizeof(sockaddr_in);
    std::memset(&addr, 0, sizeof(sockaddr_in));

    sock_t afd = ::accept(fd, (sockaddr *)&addr, &addr_len);
    int err = errno;
    debug("Socket::accept", fd, afd, err, ::strerror(err));

    if (afd < 0)
    {
      if (err == EAGAIN)
      {
        return 0;
      }
      throw SocketException(err, "accept() failed");
    }

    int status = ::fcntl(afd, F_SETFL, ::fcntl(afd, F_GETFL, 0) | O_NONBLOCK);
    err = errno;
    debug("Socket::fcntl(O_NONBLOCK)", fd, afd, err, ::strerror(err));
    if (status < 0)
    {
      throw SocketException(err, "fcntl(O_NONBLOCK) failed");
    }

    // struct linger sl;
    // sl.l_onoff = 0;  // disable linger
    // sl.l_linger = 1; // timeout in seconds
    // status = ::setsockopt(afd, SOL_SOCKET, SO_LINGER, &sl, sizeof(sl));
    // err = errno;
    // debug("Socket::setsockopt(SO_LINGER)", fd, afd, err, ::strerror(err));
    // if (status < 0)
    // {
    //   throw SocketException(err, "setsockopt(SO_LINGER) failed");
    // }

    return afd;
  }

  static int close(sock_t fd)
  {
    ::shutdown(fd, SHUT_WR);
    int ret = ::close(fd);
    int err = errno;
    if (ret < 0)
    {
      debug("Socket::close", fd, ret, err, ::strerror(err));
      if (err == EBADF)
      {
        throw SocketException(err, "close() failed");
      }
    }
    else
    {
      debug("Socket::close", fd, ret);
    }
    return 0;
  }

  static const std::string getpeername(sock_t fd)
  {
    sockaddr_in addr;
    socklen_t addr_size = sizeof(sockaddr_in);
    ::getpeername(fd, (sockaddr *)&addr, &addr_size);
    uint16_t port = addr.sin_port;
    in_addr_t *saddr = &addr.sin_addr.s_addr;
    char ip_str[INET_ADDRSTRLEN];
    const char *clientip = ::inet_ntop(AF_INET, saddr, ip_str, INET_ADDRSTRLEN);
    return std::string{clientip} + std::string{":"} + std::to_string(port);
  }
};

} // namespace Netpp