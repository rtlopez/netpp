#pragma once

#include <sys/epoll.h>
#include <unordered_map>

#include "EventLoop.h"
#include "EventLoopHandler.h"
#include "Exception.h"
#include "Netpp/Logger/Logger.h"

// https://medium.com/@m-ibrahim.research/mastering-epoll-the-engine-behind-high-performance-linux-networking-85a15e6bde90

namespace Netpp
{

using Netpp::Logger::logger;
using Netpp::Logger::LogLevel;
static const char *EPOLL = "epoll";

class EventLoopEpoll : public EventLoop
{
public:
  EventLoopEpoll() : _fd(-1), _running(true), _timeout(30000)
  {
    sock_t fd = ::epoll_create1(0);
    int err = errno;

    logger(EPOLL, LogLevel::TRACE).log(fd);

    if (fd < 0)
    {
      throw EventLoopException(err, "epoll_create1() failed");
    }

    _fd = fd;
  }

  virtual ~EventLoopEpoll()
  {
    logger(EPOLL, LogLevel::TRACE).log(_fd);
    if (_fd >= 0)
    {
      ::close(_fd);
    }
  }

  void add(sock_t fd, EventLoopHandler *handler, bool write = false) override
  {
    if (_fd < 0)
    {
      throw EventLoopException(-1, "EventLoopEpoll not initialized");
    }

    uint32_t events = EPOLLIN | EPOLLPRI;
    if (write)
    {
      events |= EPOLLOUT;
    }

    logger(EPOLL, LogLevel::TRACE).log(fd, events);

    epoll_event event = {events, {.fd = fd}};

    if (_handlers.contains(fd))
    {
      if (epoll_ctl(_fd, EPOLL_CTL_MOD, fd, &event) < 0)
      {
        throw EventLoopException(errno, "epoll_ctl(EPOLL_CTL_MOD) failed");
      }
    }
    else
    {
      if (epoll_ctl(_fd, EPOLL_CTL_ADD, fd, &event) < 0)
      {
        throw EventLoopException(errno, "epoll_ctl(EPOLL_CTL_ADD) failed");
      }

      _handlers.emplace(fd, handler);
    }
  }

  void del(sock_t fd) override
  {
    if (_fd < 0)
    {
      throw EventLoopException(-1, "EventLoopEpoll not initialized");
    }

    logger(EPOLL, LogLevel::TRACE).log(fd);

    if (epoll_ctl(_fd, EPOLL_CTL_DEL, fd, nullptr) < 0)
    {
      throw EventLoopException(errno, "epoll_ctl(EPOLL_CTL_DEL) failed");
    }

    _handlers.erase(fd);
  }

  void run() override
  {
    if (_fd < 0)
    {
      throw EventLoopException(-1, "EventLoopEpoll not initialized");
    }

    while (_running)
    {
      int ret = ::epoll_wait(_fd, _events, MAX_EVENTS, _timeout);
      if (ret == -1)
      {
        int err = errno;
        logger(EPOLL, LogLevel::ERROR).log(ret, err);
        if (err == EINTR)
        {
          continue; // interrupted, try again
        }
        throw EventLoopException(err, "epoll_wait() failed");
      }

      if (ret == 0)
      {
        // `epoll_wait` reached its timeout
        logger(EPOLL, LogLevel::TRACE).log("timeout", ret);
        continue;
      }

      for (int i = 0; i < ret; i++)
      {
        handle(_events[i]);
      }
    }
  }

  void handle(const epoll_event &ev)
  {
    logger(EPOLL, LogLevel::TRACE).log(ev.data.fd, ev.events);
    EventLoopHandler *handler = _handlers[ev.data.fd];
    if (ev.events & (EPOLLERR | EPOLLHUP))
    {
      handler->handleError(ev.data.fd);
      return;
    }
    if (ev.events & EPOLLOUT)
    {
      handler->handleWriting(ev.data.fd);
    }
    if (ev.events & (EPOLLIN | EPOLLPRI))
    {
      handler->handleReading(ev.data.fd);
    }
  }

  void stop() override
  {
    _running = false;
  }

private:
  static const size_t MAX_EVENTS = 32;
  sock_t _fd;
  volatile bool _running;
  int _timeout;
  epoll_event _events[MAX_EVENTS];
  std::unordered_map<sock_t, EventLoopHandler *> _handlers;
};

} // namespace Netpp
