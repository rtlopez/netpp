#pragma once

#include <atomic>
#include <cassert>
#include <csignal>
#include <initializer_list>
#include <mutex>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/signalfd.h>
#include <unistd.h>
#include <vector>

#include "Exception.h"
#include "Netpp/EventLoopHandler.h"
#include "Netpp/Logger/Logger.h"
#include "Netpp/Types.h"

// https://medium.com/@m-ibrahim.research/mastering-epoll-the-engine-behind-high-performance-linux-networking-85a15e6bde90

namespace Netpp
{

using Netpp::Logger::logger;
using Netpp::Logger::LogLevel;

class EventLoop
{
public:
  static constexpr const char *LOOP = "loop";

  EventLoop() : _handlers(1024)
  {
    _fd = ::epoll_create1(0);

    if (_fd < 0)
    {
      int err = errno;
      logger(LOOP, LogLevel::ERROR, _fd, err, ::strerror(err));
      throw EventLoopException(err, "epoll_create1() failed");
    }
    enableWakeUp();
    enableSignals({SIGINT, SIGTERM});
  }

  virtual ~EventLoop()
  {
    logger(LOOP, LogLevel::TRACE, _fd, _event_fd, _signal_fd);
    if (_signal_fd >= 0)
    {
      del(_signal_fd, false);
      ::close(_signal_fd);
    }
    if (_event_fd >= 0)
    {
      del(_event_fd, false);
      ::close(_event_fd);
    }
    ::close(_fd);
  }

  void enableWakeUp()
  {
    _event_fd = ::eventfd(0, EFD_NONBLOCK);
    if (_event_fd < 0)
    {
      int err = errno;
      logger(LOOP, LogLevel::ERROR, _event_fd, err, ::strerror(err));
      throw EventLoopException(err, "eventfd() failed");
    }
    add(_event_fd, nullptr, false);
  }

  void enableSignals(std::initializer_list<int> signals)
  {
    sigset_t mask;
    ::sigemptyset(&mask);
    for (int sig : signals)
    {
      ::sigaddset(&mask, sig);
    }

    if (::sigprocmask(SIG_BLOCK, &mask, nullptr) < 0)
    {
      throw EventLoopException(errno, "sigprocmask() failed");
    }

    _signal_fd = ::signalfd(-1, &mask, SFD_NONBLOCK);
    if (_signal_fd < 0)
    {
      throw EventLoopException(errno, "signalfd() failed");
    }
    add(_signal_fd, nullptr, false);
  }

  void add(fd_t fd, EventLoopHandler *handler, bool refCount = true)
  {
    assert(_fd >= 0);

    uint32_t events = EPOLLIN | EPOLLPRI;

    logger(LOOP, LogLevel::TRACE, fd, events, "read");

    epoll_event event = {events, {.fd = fd}};

    if (!getHandler(fd))
    {
      if (epoll_ctl(_fd, EPOLL_CTL_ADD, fd, &event) < 0)
      {
        auto err = errno;
        logger(LOOP, LogLevel::ERROR, fd, events, err, ::strerror(err));
        throw EventLoopException(err, std::string("epoll_ctl(LOOP_CTL_ADD) failed fd=") + std::to_string(fd));
      }
      addHandler(fd, handler);

      if (refCount)
      {
        _activeRefCount.fetch_add(1, std::memory_order_relaxed);
      }
    }
    else
    {
      if (epoll_ctl(_fd, EPOLL_CTL_MOD, fd, &event) < 0)
      {
        auto err = errno;
        logger(LOOP, LogLevel::ERROR, fd, events, err, ::strerror(err));
        throw EventLoopException(err, std::string("epoll_ctl(LOOP_CTL_MOD) failed fd=") + std::to_string(fd));
      }
    }
  }

  void mod(fd_t fd, bool write = false)
  {
    assert(_fd >= 0);

    uint32_t events = EPOLLIN | EPOLLPRI;
    if (write)
    {
      events |= EPOLLOUT;
    }
    epoll_event event = {events, {.fd = fd}};

    logger(LOOP, LogLevel::TRACE, fd, events, write ? "write" : "read");

    if (epoll_ctl(_fd, EPOLL_CTL_MOD, fd, &event) < 0)
    {
      int err = errno;
      logger(LOOP, LogLevel::WARN, fd, "ignore", err, ::strerror(err));
    }
  }

  void del(fd_t fd, bool refCount = true)
  {
    assert(_fd >= 0);

    logger(LOOP, LogLevel::TRACE, fd);

    if (epoll_ctl(_fd, EPOLL_CTL_DEL, fd, nullptr) < 0)
    {
      int err = errno;
      // EBADF: fd already closed; ENOENT: fd was never registered — both are benign
      if (err != EBADF && err != ENOENT)
      {
        // throw EventLoopException(err, "epoll_ctl(LOOP_CTL_DEL) failed");
        assert(false && "epoll_ctl(LOOP_CTL_DEL) failed");
      }
      logger(LOOP, LogLevel::WARN, "epoll_ctl(LOOP_CTL_DEL) ignored", fd, err, ::strerror(err));
    }

    removeHandler(fd);

    if (refCount)
    {
      _activeRefCount.fetch_sub(1, std::memory_order_relaxed);
    }
  }

  void run()
  {
    if (_fd < 0)
    {
      throw EventLoopException(-1, "EventLoop not initialized");
    }

    while (_running.load(std::memory_order_relaxed))
    {
      int ret = ::epoll_wait(_fd, _events, MAX_EVENTS, _timeout);
      if (ret == -1)
      {
        int err = errno;
        logger(LOOP, LogLevel::ERROR, "err", ret, err);
        if (err == EINTR)
        {
          continue; // interrupted, try again
        }
        throw EventLoopException(err, "epoll_wait() failed");
      }

      if (ret == 0)
      {
        // `epoll_wait` reached its timeout
        logger(LOOP, LogLevel::TRACE, "loop timeout");
        continue;
      }

      for (int i = 0; i < ret; i++)
      {
        handle(_events[i]);
      }

      if (_activeRefCount.load(std::memory_order_relaxed) == 0)
      {
        logger(LOOP, LogLevel::INFO, "loop auto-stopping");
        break;
      }
    }
  }

  void stop()
  {
    _running.store(false, std::memory_order_relaxed);
    wake();
  }

  void wake()
  {
    uint64_t val = 1;
    auto n = ::write(_event_fd, &val, sizeof(val));
    if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
    {
      logger(LOOP, LogLevel::WARN, errno, ::strerror(errno));
    }
  }

private:
  void handle(const epoll_event &ev)
  {
    if (ev.data.fd == _event_fd)
    {
      handleWake();
      return;
    }

    if (ev.data.fd == _signal_fd)
    {
      handleSignal();
      return;
    }

    auto handler = getHandler(ev.data.fd);
    logger(LOOP, LogLevel::TRACE, ev.data.fd, ev.events, !!handler);
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

  void handleWake()
  {
    uint64_t val;
    auto n = ::read(_event_fd, &val, sizeof(val));
    if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
    {
      logger(LOOP, LogLevel::WARN, _event_fd, errno, ::strerror(errno));
    }
  }

  void handleSignal()
  {
    signalfd_siginfo info;
    ssize_t len = ::read(_signal_fd, &info, sizeof(info));
    if (len == sizeof(info))
    {
      logger(LOOP, LogLevel::INFO, "Caught signal", info.ssi_signo);
      _running.store(false, std::memory_order_relaxed);
    }
  }

  EventLoopHandler *getHandler(fd_t fd)
  {
    if (fd < 0)
    {
      throw EventLoopException(-1, "invalid fd");
    }

    std::scoped_lock lock(_handlersMutex);
    if (static_cast<size_t>(fd) >= _handlers.size())
    {
      return nullptr;
    }
    return _handlers[fd];
  }

  void addHandler(fd_t fd, EventLoopHandler *handler)
  {
    if (fd < 0)
    {
      throw EventLoopException(-1, "invalid fd");
    }

    std::scoped_lock lock(_handlersMutex);
    if (static_cast<size_t>(fd) >= _handlers.size())
    {
      _handlers.resize(static_cast<size_t>(fd) + 1024, nullptr);
    }
    _handlers[fd] = handler;
  }

  void removeHandler(fd_t fd)
  {
    if (fd < 0)
    {
      return;
    }

    std::scoped_lock lock(_handlersMutex);
    if (static_cast<size_t>(fd) >= _handlers.size())
    {
      return;
    }
    _handlers[fd] = nullptr;
  }

  static const size_t MAX_EVENTS = 64;

  fd_t _fd{-1};
  fd_t _event_fd{-1};
  fd_t _signal_fd{-1};
  std::atomic<bool> _running{true};
  std::atomic<size_t> _activeRefCount{0};
  int _timeout{-1};
  epoll_event _events[MAX_EVENTS]{};
  std::vector<EventLoopHandler *> _handlers{};
  std::mutex _handlersMutex{};
};

} // namespace Netpp
