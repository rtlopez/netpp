#pragma once

#include <atomic>
#include <csignal>
#include <initializer_list>
#include <mutex>
#include <optional>
#include <sys/epoll.h>
#include <vector>

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

  EventLoop();
  ~EventLoop();

  void add(fd_t fd, EventLoopHandler *handler, bool refCount = true);
  void mod(fd_t fd, bool write = false);
  void del(fd_t fd, bool refCount = true);
  void run();
  void stop();
  void notify();

private:
  void handle(const epoll_event &ev);

  EventLoopHandler *getHandler(fd_t fd);
  void addHandler(fd_t fd, EventLoopHandler *handler);
  void removeHandler(fd_t fd);

  class NotifyHandler : public EventLoopHandler
  {
  public:
    explicit NotifyHandler(EventLoop *loop);
    ~NotifyHandler() override;
    void handle(fd_t fd, LoopEventType) override;
    void notify();

  private:
    EventLoop *_loop{nullptr};
    fd_t _fd{-1};
  };

  class SignalHandler : public EventLoopHandler
  {
  public:
    SignalHandler(EventLoop *loop, std::initializer_list<int> signals);
    ~SignalHandler() override;
    void handle(fd_t fd, LoopEventType) override;

  private:
    EventLoop *_loop{nullptr};
    fd_t _fd{-1};
  };

  static const size_t MAX_EVENTS = 64;

  fd_t _fd{-1};
  std::atomic<bool> _running{true};
  std::atomic<size_t> _activeRefCount{0};
  int _timeout{-1};
  epoll_event _events[MAX_EVENTS]{};
  std::vector<EventLoopHandler *> _handlers{};
  std::mutex _handlersMutex{};
  std::optional<NotifyHandler> _wakeHandler;
  std::optional<SignalHandler> _signalHandler;
};

} // namespace Netpp
