#pragma once

#include <sys/eventfd.h>
#include <unistd.h>

#include "Netpp/EventLoop.h"
#include "Netpp/EventLoopHandler.h"
#include "Netpp/Exception.h"
#include "Netpp/Logger/Logger.h"

namespace Netpp
{

using Netpp::Logger::logger;
using Netpp::Logger::LogLevel;

class LoopControlHandler : public EventLoopHandler
{
public:
  static constexpr const char *LOOP = "loop";

  explicit LoopControlHandler(EventLoop *loop) : _loop(loop), _stopCallback(loop->getStopCallback()), _fd(-1)
  {
    _fd = ::eventfd(0, EFD_NONBLOCK);
    if (_fd < 0)
    {
      int err = errno;
      logger(LOOP, LogLevel::ERROR, _fd, err, ::strerror(err));
      throw EventLoopException(err, "eventfd() failed");
    }

    logger(LOOP, LogLevel::TRACE, _fd);
    _loop->add(_fd, this);
  }

  ~LoopControlHandler()
  {
    logger(LOOP, LogLevel::TRACE, _fd);
    _loop->del(_fd);
    ::close(_fd);
  }

  void stop()
  {
    if (_stopCallback)
    {
      _stopCallback();
    }
    wake();
  }

  void wake()
  {
    uint64_t val = 1;
    auto n = ::write(_fd, &val, sizeof(val));
    if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
    {
      logger(LOOP, LogLevel::WARN, "wake:write", errno, ::strerror(errno));
    }
  }

  void handleReading(sock_t s) override
  {
    uint64_t val;
    auto n = ::read(s, &val, sizeof(val));
    if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
    {
      logger(LOOP, LogLevel::WARN, "wake:read", errno, ::strerror(errno));
    }
  }

  void handleWriting(sock_t) override
  {
  }

  void handleError(sock_t s) override
  {
    logger(LOOP, LogLevel::WARN, "control:error", s);
    if (_stopCallback)
    {
      _stopCallback();
    }
  }

private:
  EventLoop *_loop;
  EventLoop::StopCallback _stopCallback;
  sock_t _fd;
};

} // namespace Netpp
