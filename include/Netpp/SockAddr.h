#pragma once

#include <cstring>
#include <stdexcept>
#include <string>

#include <arpa/inet.h>
#include <netinet/in.h>

namespace Netpp
{

/// Lightweight value wrapper around sockaddr_storage.
/// Holds either an IPv4 (AF_INET) or IPv6 (AF_INET6) address.
class SockAddr
{
public:
  SockAddr() = default;

  SockAddr(const sockaddr *sa, socklen_t len) : _len(len)
  {
    std::memcpy(&_storage, sa, len);
  }

  /// Build a SockAddr from a numeric host string and port.
  /// Auto-detects IPv4 vs IPv6 using inet_pton().
  static SockAddr from(const char *host, uint16_t port)
  {
    SockAddr sa;

    // Try IPv6 first (IPv4 literals never contain ':')
    if (std::strchr(host, ':'))
    {
      auto &a6 = sa.as<sockaddr_in6>();
      if (::inet_pton(AF_INET6, host, &a6.sin6_addr) != 1)
      {
        throw std::invalid_argument(std::string("invalid IPv6 address: ") + host);
      }
      a6.sin6_family = AF_INET6;
      a6.sin6_port = htons(port);
      sa._len = sizeof(sockaddr_in6);
    }
    else
    {
      auto &a4 = sa.as<sockaddr_in>();
      if (::inet_pton(AF_INET, host, &a4.sin_addr) != 1)
      {
        throw std::invalid_argument(std::string("invalid IPv4 address: ") + host);
      }
      a4.sin_family = AF_INET;
      a4.sin_port = htons(port);
      sa._len = sizeof(sockaddr_in);
    }

    return sa;
  }

  int family() const
  {
    return _storage.ss_family;
  }

  uint16_t port() const
  {
    if (family() == AF_INET6)
    {
      return ntohs(reinterpret_cast<const sockaddr_in6 *>(&_storage)->sin6_port);
    }
    return ntohs(reinterpret_cast<const sockaddr_in *>(&_storage)->sin_port);
  }

  sockaddr *addr()
  {
    return reinterpret_cast<sockaddr *>(&_storage);
  }

  const sockaddr *addr() const
  {
    return reinterpret_cast<const sockaddr *>(&_storage);
  }

  socklen_t len() const
  {
    return _len;
  }

  socklen_t &len()
  {
    return _len;
  }

  /// Human-readable representation: "1.2.3.4:80" or "[::1]:80"
  std::string toString() const
  {
    if (family() == AF_INET6)
    {
      const auto *a6 = reinterpret_cast<const sockaddr_in6 *>(&_storage);
      char buf[INET6_ADDRSTRLEN];
      ::inet_ntop(AF_INET6, &a6->sin6_addr, buf, sizeof(buf));
      return std::string("[") + buf + "]:" + std::to_string(ntohs(a6->sin6_port));
    }

    if (family() == AF_INET)
    {
      const auto *a4 = reinterpret_cast<const sockaddr_in *>(&_storage);
      char buf[INET_ADDRSTRLEN];
      ::inet_ntop(AF_INET, &a4->sin_addr, buf, sizeof(buf));
      return std::string(buf) + ":" + std::to_string(ntohs(a4->sin_port));
    }

    return "(unknown)";
  }

  /// Check if a string is a valid numeric IPv4 or IPv6 address.
  static bool isValidIP(const char *host)
  {
    struct in_addr v4;
    if (::inet_pton(AF_INET, host, &v4) == 1)
    {
      return true;
    }
    struct in6_addr v6;
    return ::inet_pton(AF_INET6, host, &v6) == 1;
  }

  /// Reset to a zeroed state suitable for accept()/recvfrom() output.
  void reset()
  {
    _storage = {};
    _len = sizeof(_storage);
  }

private:
  template <typename T>
  T &as()
  {
    return *reinterpret_cast<T *>(&_storage);
  }

  sockaddr_storage _storage{};
  socklen_t _len = 0;
};

} // namespace Netpp
