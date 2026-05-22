#pragma once

#include <cstring>
#include <stdexcept>

namespace Netpp
{

class ErrnoException : public std::runtime_error
{
public:
  ErrnoException(int erno, const std::string msg)
      : std::runtime_error(msg + ": (" + std::to_string(erno) + ":" + std::to_string(erno) + ") " +
                           std::strerror(erno)),
        _errno(erno)
  {
  }

  int errNo() const
  {
    return _errno;
  }

  const char *errStr() const
  {
    return std::strerror(_errno);
  }

private:
  int _errno;
};

class SocketException : public ErrnoException
{
public:
  SocketException(int eno, const std::string &msg) : ErrnoException(eno, msg)
  {
  }
};

class EventLoopException : public ErrnoException
{
public:
  EventLoopException(int eno, const std::string &msg) : ErrnoException(eno, msg)
  {
  }
};

} // namespace Netpp
