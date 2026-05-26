#pragma once

#include <csignal>
#include <cstdio>
#include <initializer_list>
#include <sys/signalfd.h>
#include <unistd.h>

#include "Netpp/EventLoop.h"
#include "Netpp/EventLoopHandler.h"
#include "Netpp/Exception.h"
#include "Netpp/NetppDebug.h"
#include "Netpp/Socket.h"

namespace Netpp
{

class SignalHandler : public EventLoopHandler
{
public:
  SignalHandler(EventLoop *loop, std::initializer_list<int> signals)
      : _loop(loop), _fd(-1)
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

    debug("SignalHandler", _fd);
    _loop->add(_fd, this);
  }

  ~SignalHandler()
  {
    debug("~SignalHandler", _fd);
    if (_fd >= 0)
    {
      _loop->del(_fd);
      ::close(_fd);
    }
  }

  void handle(sock_t s) override
  {
    signalfd_siginfo info;
    ssize_t len = ::read(s, &info, sizeof(info));
    if (len == sizeof(info))
    {
      debug("SignalHandler", "signal", info.ssi_signo);
      std::printf("Caught signal %d, shutting down...\n", info.ssi_signo);
      _loop->stop();
    }
  }

  void handleError(sock_t) override
  {
    _loop->stop();
  }

private:
  EventLoop *_loop;
  sock_t _fd;
};

} // namespace Netpp
