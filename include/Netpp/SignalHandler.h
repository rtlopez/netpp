#pragma once

#include <csignal>
#include <cstdio>
#include <initializer_list>
#include <sys/signalfd.h>
#include <unistd.h>

#include "Netpp/EventLoop.h"
#include "Netpp/EventLoopHandler.h"
#include "Netpp/Exception.h"
#include "Netpp/Logger/Logger.h"
#include "Netpp/LoopControlHandler.h"
#include "Netpp/Socket.h"

namespace Netpp
{

using Netpp::Logger::logger;
using Netpp::Logger::LogLevel;
static const char *SIGNAL = "signal";

class SignalHandler : public EventLoopHandler
{
public:
  SignalHandler(EventLoop *loop, LoopControlHandler *loopControl, std::initializer_list<int> signals)
      : _loop(loop), _loopControl(loopControl), _fd(-1)
  {
    sigset_t mask;
    sigemptyset(&mask);
    for (int sig : signals)
    {
      sigaddset(&mask, sig);
    }

    if (sigprocmask(SIG_BLOCK, &mask, nullptr) < 0)
    {
      throw EventLoopException(errno, "sigprocmask() failed");
    }

    _fd = signalfd(-1, &mask, SFD_NONBLOCK);
    if (_fd < 0)
    {
      throw EventLoopException(errno, "signalfd() failed");
    }

    logger(SIGNAL, LogLevel::DEBUG, _fd);
    _loop->add(_fd, this);
  }

  ~SignalHandler()
  {
    logger(SIGNAL, LogLevel::DEBUG, _fd);
    if (_fd >= 0)
    {
      _loop->del(_fd);
      ::close(_fd);
    }
  }

  void handleReading(sock_t s) override
  {
    signalfd_siginfo info;
    ssize_t len = ::read(s, &info, sizeof(info));
    if (len == sizeof(info))
    {
      logger(SIGNAL, LogLevel::INFO, "Caught signal", info.ssi_signo);
      _loopControl->stop();
    }
  }

  void handleError(sock_t s) override
  {
    logger(SIGNAL, LogLevel::ERROR, "Error in signal handler", s);
    _loopControl->stop();
  }

  void handleWriting(sock_t) override
  {
  }

private:
  EventLoop *_loop;
  LoopControlHandler *_loopControl;
  sock_t _fd;
};

} // namespace Netpp
