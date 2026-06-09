#pragma once

#include <mutex>
#include <sys/epoll.h>
#include <vector>

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
  EventLoopEpoll() : _fd(-1), _running(true), _timeout(30000), _handlers(1024)
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

    logger(EPOLL, LogLevel::TRACE).log(fd, events, write ? "write" : "read");

    epoll_event event = {events, {.fd = fd}};

    if (!getHandler(fd))
    {
      if (epoll_ctl(_fd, EPOLL_CTL_ADD, fd, &event) < 0)
      {
        auto err = errno;
        logger(EPOLL, LogLevel::ERROR).log(fd, events, err, ::strerror(err));
        throw EventLoopException(err, std::string("epoll_ctl(EPOLL_CTL_ADD) failed fd=") + std::to_string(fd));
      }
      addHandler(fd, handler);
    }
    else
    {
      if (epoll_ctl(_fd, EPOLL_CTL_MOD, fd, &event) < 0)
      {
        auto err = errno;
        logger(EPOLL, LogLevel::ERROR).log(fd, events, err, ::strerror(err));
        throw EventLoopException(err, std::string("epoll_ctl(EPOLL_CTL_MOD) failed fd=") + std::to_string(fd));
      }
    }
  }

  void notify(sock_t fd) override
  {
    if (_fd < 0)
    {
      throw EventLoopException(-1, "EventLoopEpoll not initialized");
    }

    epoll_event event = {EPOLLIN | EPOLLPRI | EPOLLOUT, {.fd = fd}};

    logger(EPOLL, LogLevel::TRACE).log(fd, event.events);

    if (epoll_ctl(_fd, EPOLL_CTL_MOD, fd, &event) < 0)
    {
      int err = errno;
      logger(EPOLL, LogLevel::WARN).log(fd, "ignore", err, ::strerror(err));
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
      int err = errno;
      // EBADF: fd already closed; ENOENT: fd was never registered — both are benign
      if (err != EBADF && err != ENOENT)
      {
        throw EventLoopException(err, "epoll_ctl(EPOLL_CTL_DEL) failed");
      }
      logger(EPOLL, LogLevel::WARN).log("epoll_ctl(EPOLL_CTL_DEL) ignored", fd, err, ::strerror(err));
    }

    removeHandler(fd);
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
        logger(EPOLL, LogLevel::ERROR).log("err", ret, err);
        if (err == EINTR)
        {
          continue; // interrupted, try again
        }
        throw EventLoopException(err, "epoll_wait() failed");
      }

      if (ret == 0)
      {
        // `epoll_wait` reached its timeout
        logger(EPOLL, LogLevel::TRACE).log("timeout");
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
    auto handler = getHandler(ev.data.fd);
    logger(EPOLL, LogLevel::TRACE).log(ev.data.fd, ev.events, !!handler);
    if (!handler)
    {
      return;
    }

    if (ev.events & (EPOLLERR | EPOLLHUP))
    {
      handler->handleError(ev.data.fd);
      return;
    }

    if (ev.events & EPOLLOUT)
    {
      handler->handleWriting(ev.data.fd);
    }

    // re-check: handleWriting may have closed and removed this fd
    handler = getHandler(ev.data.fd);
    if (!handler)
    {
      return;
    }

    if (ev.events & (EPOLLIN | EPOLLPRI))
    {
      handler->handleReading(ev.data.fd);
    }
  }

  EventLoopHandler *getHandler(sock_t fd)
  {
    std::scoped_lock lock(_handlersMutex);
    if (fd < 0)
    {
      throw EventLoopException(-1, "invalid fd");
    }
    if (static_cast<size_t>(fd) >= _handlers.size())
    {
      return nullptr;
    }
    return _handlers[fd];
  }

  void addHandler(sock_t fd, EventLoopHandler *handler)
  {
    if (fd < 0)
    {
      throw EventLoopException(-1, "invalid fd");
    }

    if (static_cast<size_t>(fd) >= _handlers.size())
    {
      std::scoped_lock lock(_handlersMutex);
      _handlers.resize(static_cast<size_t>(fd) + 1024, nullptr);
    }
    _handlers[fd] = handler;
  }

  void removeHandler(sock_t fd)
  {
    std::scoped_lock lock(_handlersMutex);
    if (fd < 0 || static_cast<size_t>(fd) >= _handlers.size())
    {
      return;
    }
    _handlers[fd] = nullptr;
  }

  void stop() override
  {
    _running = false;
  }

private:
  static const size_t MAX_EVENTS = 64;
  sock_t _fd;
  volatile bool _running;
  int _timeout;
  epoll_event _events[MAX_EVENTS];
  std::vector<EventLoopHandler *> _handlers;
  std::mutex _handlersMutex;
};

} // namespace Netpp
