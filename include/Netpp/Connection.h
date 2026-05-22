#pragma once

#include "Socket.h"

namespace Netpp
{

class Connection
{
public:
  Connection(sock_t s) : _s(s)
  {
  }

  virtual ~Connection()
  {
    close();
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

  void close()
  {
    // TODO: notify handler to close connection
    Socket::close(_s);
  }
private:
  sock_t _s;
};

} // namespace Netpp
