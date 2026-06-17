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
#include "Netpp/MoveOnlyFunction.h"
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

  class GenericEventLoopHandler : public EventLoopHandler
  {
  public:
    using HandleCallbackType = MoveOnlyFunction<void(fd_t, LoopEventType)>;

    GenericEventLoopHandler() = default;
    GenericEventLoopHandler(GenericEventLoopHandler &&) = default;
    GenericEventLoopHandler &operator=(GenericEventLoopHandler &&) = default;
    GenericEventLoopHandler(fd_t fd, EventLoop *loop, HandleCallbackType cb) : _fd{fd}, _loop{loop}, _cb{std::move(cb)}
    {
      _loop->add(_fd, this, false);
    }

    GenericEventLoopHandler(const GenericEventLoopHandler &) = delete;
    GenericEventLoopHandler &operator=(const GenericEventLoopHandler &) = delete;

    virtual ~GenericEventLoopHandler()
    {
      if (_fd >= 0)
      {
        _loop->del(_fd, false);
        ::close(_fd);
      }
    }

    void handle(fd_t s, LoopEventType t) override
    {
      _cb(s, t);
    }

  private:
    fd_t _fd{-1};
    EventLoop *_loop;
    HandleCallbackType _cb;
  };

  EventLoop() : _handlers(1024)
  {
    _fd = ::epoll_create1(0);

    if (_fd < 0)
    {
      int err = errno;
      logger(LOOP, LogLevel::ERROR, _fd, err, ::strerror(err));
      throw EventLoopException(err, "epoll_create1() failed");
    }
    // enableWakeUp();
    // enableSignals({SIGINT, SIGTERM});
    _wakeHandler =
        GenericEventLoopHandler(createWakeFd(), this, [this](fd_t fd, LoopEventType t) { handleWake(fd, t); });
    _signalHandler = GenericEventLoopHandler(createSignalFd({SIGINT, SIGTERM}), this,
                                             [this](fd_t fd, LoopEventType t) { handleSignal(fd, t); });
  }

  virtual ~EventLoop()
  {
    logger(LOOP, LogLevel::TRACE, _fd /*, _event_fd, _signal_fd*/);
    // if (_signal_fd >= 0)
    // {
    //   del(_signal_fd, false);
    //   ::close(_signal_fd);
    // }
    // if (_event_fd >= 0)
    // {
    //   del(_event_fd, false);
    //   ::close(_event_fd);
    // }
    _signalHandler = {};
    _wakeHandler = {};
    ::close(_fd);
  }

  fd_t createWakeFd()
  {
    fd_t fd = ::eventfd(0, EFD_NONBLOCK);
    if (fd < 0)
    {
      int err = errno;
      logger(LOOP, LogLevel::ERROR, fd, err, ::strerror(err));
      throw EventLoopException(err, "eventfd() failed");
    }
    return fd;
  }

  // void enableWakeUp()
  // {
  //   _event_fd = createWakeFd();
  //   add(_event_fd, nullptr, false);
  // }

  fd_t createSignalFd(std::initializer_list<int> signals)
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

    fd_t fd = ::signalfd(-1, &mask, SFD_NONBLOCK);
    if (fd < 0)
    {
      throw EventLoopException(errno, "signalfd() failed");
    }
    return fd;
  }

  // void enableSignals(std::initializer_list<int> signals)
  // {
  //   _signal_fd = createSignalFd(signals);
  //   add(_signal_fd, nullptr, false);
  // }

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
    // if (ev.data.fd == _event_fd)
    // {
    //   handleWake(_event_fd, LoopEventType::READ);
    //   return;
    // }

    // if (ev.data.fd == _signal_fd)
    // {
    //   handleSignal(_signal_fd, LoopEventType::READ);
    //   return;
    // }

    auto handler = getHandler(ev.data.fd);
    if (!handler)
    {
      logger(LOOP, LogLevel::DEBUG, ev.data.fd, ev.events, !!handler);
      return;
    }

    if (ev.events & (EPOLLERR | EPOLLHUP))
    {
      logger(LOOP, LogLevel::DEBUG, ev.data.fd, ev.events, "err");
      handler->handle(ev.data.fd, LoopEventType::ERROR);
      return;
    }

    if (ev.events & EPOLLOUT)
    {
      handler->handle(ev.data.fd, LoopEventType::WRITE);
    }

    // re-check: handle WRITE/ERROR may have closed and removed fd from loop
    handler = getHandler(ev.data.fd);
    if (!handler)
    {
      return;
    }

    if (ev.events & (EPOLLIN | EPOLLPRI))
    {
      handler->handle(ev.data.fd, LoopEventType::READ);
    }
  }

  void handleWake(fd_t fd, LoopEventType)
  {
    uint64_t val;
    auto n = ::read(fd, &val, sizeof(val));
    if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
    {
      logger(LOOP, LogLevel::WARN, fd, errno, ::strerror(errno));
    }
  }

  void handleSignal(fd_t fd, LoopEventType)
  {
    signalfd_siginfo info;
    ssize_t len = ::read(fd, &info, sizeof(info));
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
  // fd_t _event_fd{-1};
  // fd_t _signal_fd{-1};
  std::atomic<bool> _running{true};
  std::atomic<size_t> _activeRefCount{0};
  int _timeout{-1};
  epoll_event _events[MAX_EVENTS]{};
  std::vector<EventLoopHandler *> _handlers{};
  std::mutex _handlersMutex{};
  GenericEventLoopHandler _wakeHandler;
  GenericEventLoopHandler _signalHandler;
};

} // namespace Netpp
