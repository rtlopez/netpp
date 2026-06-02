#pragma once

#include <memory>
#include <string>

#include "Netpp/Logger/Logger.h"
#include "Socket.h"

namespace Netpp
{

using Netpp::Logger::logger;
using Netpp::Logger::LogLevel;
static const char *CONNECTION = "connection";

class Connection
{
public:
  Connection(sock_t s) : _s(s)
  {
    logger(CONNECTION, LogLevel::DEBUG).log(_s);
  }

  virtual ~Connection()
  {
    logger(CONNECTION, LogLevel::DEBUG).log(_s);
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

private:
  sock_t _s;
};

using ConnectionPtr = std::shared_ptr<Connection>;

} // namespace Netpp
