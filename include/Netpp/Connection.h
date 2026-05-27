#pragma once

#include <memory>
#include <string>

#include "Socket.h"

namespace Netpp
{

class Connection
{
public:
  Connection(sock_t s) : _s(s)
  {
    debug("Connection", _s);
  }

  virtual ~Connection()
  {
    debug("~Connection", _s);
    if (_s >= 0)
    {
      Socket::close(_s);
      _s = -1;
    }
  }

  std::string getPeerName() const
  {
    return Socket::getpeername(_s);
  }

  int getId() const
  {
    return static_cast<int>(_s);
  }

  bool operator==(const Connection &other) const
  {
    return _s == other._s;
  }

  bool operator!=(const Connection &other) const
  {
    return !this->operator==(other);
  }

  int send(const void *buf, size_t len, int flags)
  {
    // TODO: write to buffer instead of sending directly
    return Socket::send(_s, buf, len, flags);
  }

  int recv(void *buf, size_t len, int flags)
  {
    // TODO: read from buffer instead of reading directly
    return Socket::recv(_s, buf, len, flags);
  }

private:
  sock_t _s;
};

using ConnectionPtr = std::shared_ptr<Connection>;

} // namespace Netpp
