#pragma once

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

  int send(const char *buf, size_t len, int flags)
  {
    // TODO: write to buffer instead of sending directly
    return Socket::send(_s, buf, len, flags);
  }

  int recv(char *buf, size_t len, int flags)
  {
    // TODO: read from buffer instead of reading directly
    return Socket::recv(_s, buf, len, flags);
  }

  void setError()
  {
    _error = true;
  }

  bool hasError() const
  {
    return _error;
  }

  void setClosed()
  {
    // TODO: notify handler to close connection
    // Socket::close(_s);
    _close = true;
  }

  bool isClosed() const
  {
    return _close;
  }

private:
  bool _close = false;
  bool _error = false;
  sock_t _s;
};

using ConnectionPtr = std::shared_ptr<Connection>;

} // namespace Netpp
