#pragma once

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <unistd.h>

#include <cstring>
#include <string>

#include "Netpp/Exception.h"
#include "Netpp/Logger/Logger.h"
#include "Netpp/SockAddr.h"
#include "Netpp/Types.h"
namespace Netpp
{

using Netpp::Logger::logger;
using Netpp::Logger::LogLevel;
static const char *SOCKET = "socket";

class Socket
{
public:
  static fd_t create(int domain, int type, int protocol)
  {
    fd_t fd = ::socket(domain, type, protocol);
    auto err = errno;
    if (fd < 0)
    {
      logger(SOCKET, LogLevel::ERROR, domain, type, protocol, fd, err, ::strerror(err));
      throw SocketException(err, "socket() failed");
    }

    logger(SOCKET, LogLevel::TRACE, domain, type, protocol, fd);

    return fd;
  }

  static ssize_t send(fd_t fd, const void *buf, size_t len, int flags)
  {
    return ::send(fd, buf, len, flags);
  }

  static ssize_t recv(fd_t fd, void *buf, size_t len, int flags)
  {
    return ::recv(fd, buf, len, flags);
  }

  static ssize_t sendto(fd_t fd, const void *buf, size_t len, int flags, const SockAddr &addr)
  {
    return ::sendto(fd, buf, len, flags, addr.addr(), addr.len());
  }

  static ssize_t recvfrom(fd_t fd, void *buf, size_t len, int flags, SockAddr &addr)
  {
    addr.reset();
    return ::recvfrom(fd, buf, len, flags, addr.addr(), &addr.len());
  }

  static int bind(fd_t fd, const char *bind_addr, uint16_t bind_port)
  {
    const int enable = 1;
    if (::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0)
    {
      throw SocketException(errno, "setsockopt(SO_REUSEADDR) failed");
    }
    // if (::setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &enable, sizeof(int)) < 0)
    // {
    //   throw SocketException(errno, "setsockopt(SO_REUSEPORT) failed");
    // }

    auto addr = SockAddr::from(bind_addr, bind_port);

    int ret = ::bind(fd, addr.addr(), addr.len());
    int err = errno;

    if (ret < 0)
    {
      logger(SOCKET, LogLevel::ERROR, fd, ret, err, ::strerror(err));
      throw SocketException(err, "bind() failed");
    }

    logger(SOCKET, LogLevel::TRACE, fd, ret);

    return ret;
  }

  static int listen(fd_t fd, int size)
  {
    int ret = ::listen(fd, size);
    int err = errno;

    if (ret < 0)
    {
      logger(SOCKET, LogLevel::ERROR, fd, ret, err, ::strerror(err));
      throw SocketException(err, "listen() failed");
    }

    logger(SOCKET, LogLevel::TRACE, fd, ret);

    return ret;
  }

  static int accept(fd_t fd, SockAddr &addr)
  {
    addr.reset();

    fd_t afd = ::accept(fd, addr.addr(), &addr.len());
    int err = errno;

    if (afd < 0)
    {
      logger(SOCKET, LogLevel::ERROR, afd, fd, err, ::strerror(err));
      if (err == EAGAIN)
      {
        return 0;
      }
      throw SocketException(err, "accept() failed");
    }

    int status = ::fcntl(afd, F_SETFL, ::fcntl(afd, F_GETFL, 0) | O_NONBLOCK);
    err = errno;
    if (status < 0)
    {
      logger(SOCKET, LogLevel::ERROR, "fcntl(O_NONBLOCK) failed", afd, fd, err, ::strerror(err));
      throw SocketException(err, "fcntl(O_NONBLOCK) failed");
    }

    logger(SOCKET, LogLevel::TRACE, afd, fd);

    // struct linger sl;
    // sl.l_onoff = 0;  // disable linger
    // sl.l_linger = 1; // timeout in seconds
    // status = ::setsockopt(afd, SOL_SOCKET, SO_LINGER, &sl, sizeof(sl));
    // err = errno;
    // if (status < 0)
    // {
    //   throw SocketException(err, "setsockopt(SO_LINGER) failed");
    // }

    return afd;
  }

  static int connect(fd_t fd, const char *host, uint16_t port, SockAddr &addr)
  {
    addr = SockAddr::from(host, port);

    int ret = ::connect(fd, addr.addr(), addr.len());
    int err = errno;

    if (ret < 0 && err != EINPROGRESS)
    {
      logger(SOCKET, LogLevel::ERROR, fd, host, port, ret, err, ::strerror(err));
      throw SocketException(err, "connect() failed");
    }

    logger(SOCKET, LogLevel::TRACE, fd, host, port, ret);
    return ret;
  }

  static int close(fd_t fd)
  {
    ::shutdown(fd, SHUT_WR);
    int ret = ::close(fd);
    int err = errno;
    if (ret < 0)
    {
      logger(SOCKET, LogLevel::ERROR, "close() failed", fd, ret, err, ::strerror(err));
      if (err == EBADF)
      {
        throw SocketException(err, "close() failed");
      }
    }
    else
    {
      logger(SOCKET, LogLevel::TRACE, fd, ret);
    }
    return 0;
  }

  static const std::string getpeername(fd_t fd)
  {
    SockAddr addr;
    addr.reset();
    ::getpeername(fd, addr.addr(), &addr.len());
    return getpeername(addr);
  }

  static const std::string getpeername(const SockAddr &addr)
  {
    return addr.toString();
  }
};

} // namespace Netpp