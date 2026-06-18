#include "Netpp/EventLoop.h"
#include "Netpp/Exception.h"

#include <cassert>
#include <cerrno>
#include <cstring>
#include <string>

#include <sys/eventfd.h>
#include <sys/signalfd.h>
#include <unistd.h>

namespace Netpp
{

EventLoop::EventLoop() : _handlers(1024)
{
  _fd = ::epoll_create1(0);
  if (_fd < 0)
  {
    int err = errno;
    logger(LOOP, LogLevel::ERROR, _fd, err, ::strerror(err));
    throw EventLoopException(err, "epoll_create1() failed");
  }
  _wakeHandler.emplace(this);
  _signalHandler.emplace(this, std::initializer_list<int>{SIGINT, SIGTERM});
}

EventLoop::~EventLoop()
{
  logger(LOOP, LogLevel::TRACE, _fd);
  _signalHandler.reset();
  _wakeHandler.reset();
  ::close(_fd);
}

void EventLoop::add(fd_t fd, EventLoopHandler *handler, bool refCount)
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

void EventLoop::mod(fd_t fd, bool write)
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

void EventLoop::del(fd_t fd, bool refCount)
{
  assert(_fd >= 0);

  logger(LOOP, LogLevel::TRACE, fd);

  if (epoll_ctl(_fd, EPOLL_CTL_DEL, fd, nullptr) < 0)
  {
    int err = errno;
    if (err != EBADF && err != ENOENT)
    {
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

void EventLoop::run()
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
        continue;
      }
      throw EventLoopException(err, "epoll_wait() failed");
    }

    if (ret == 0)
    {
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

void EventLoop::stop()
{
  _running.store(false, std::memory_order_relaxed);
  notify();
}

void EventLoop::notify()
{
  if (_wakeHandler)
  {
    _wakeHandler->notify();
  }
}

void EventLoop::handle(const epoll_event &ev)
{
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

EventLoopHandler *EventLoop::getHandler(fd_t fd)
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

void EventLoop::addHandler(fd_t fd, EventLoopHandler *handler)
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

void EventLoop::removeHandler(fd_t fd)
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

EventLoop::NotifyHandler::NotifyHandler(EventLoop *loop) : _loop(loop)
{
  _fd = ::eventfd(0, EFD_NONBLOCK);
  if (_fd < 0)
  {
    int err = errno;
    logger(LOOP, LogLevel::ERROR, _fd, err, ::strerror(err));
    throw EventLoopException(err, "eventfd() failed");
  }
  _loop->add(_fd, this, false);
  logger(LOOP, LogLevel::TRACE, _fd);
}

EventLoop::NotifyHandler::~NotifyHandler()
{
  if (_loop && _fd >= 0)
  {
    _loop->del(_fd, false);
    ::close(_fd);
  }
}

void EventLoop::NotifyHandler::handle(fd_t fd, LoopEventType)
{
  assert(fd == _fd);
  uint64_t val;
  auto n = ::read(fd, &val, sizeof(val));
  if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
  {
    logger(LOOP, LogLevel::WARN, fd, errno, ::strerror(errno));
  }
}

void EventLoop::NotifyHandler::notify()
{
  uint64_t val = 1;
  auto n = ::write(_fd, &val, sizeof(val));
  if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
  {
    logger(LOOP, LogLevel::WARN, errno, ::strerror(errno));
  }
}

EventLoop::SignalHandler::SignalHandler(EventLoop *loop, std::initializer_list<int> signals) : _loop(loop)
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
  _fd = ::signalfd(-1, &mask, SFD_NONBLOCK);
  if (_fd < 0)
  {
    throw EventLoopException(errno, "signalfd() failed");
  }
  _loop->add(_fd, this, false);
  logger(LOOP, LogLevel::TRACE, _fd);
}

EventLoop::SignalHandler::~SignalHandler()
{
  if (_loop && _fd >= 0)
  {
    _loop->del(_fd, false);
    ::close(_fd);
  }
}

void EventLoop::SignalHandler::handle(fd_t fd, LoopEventType)
{
  assert(fd == _fd);

  signalfd_siginfo info;
  ssize_t len = ::read(fd, &info, sizeof(info));
  if (len == static_cast<ssize_t>(sizeof(info)))
  {
    logger(LOOP, LogLevel::INFO, "Caught signal", info.ssi_signo);
    _loop->_running.store(false, std::memory_order_relaxed);
  }
}

} // namespace Netpp
