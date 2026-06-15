#pragma once

#include <atomic>
#include <chrono>
#include <memory>
#include <mutex>
#include <queue>
#include <sys/timerfd.h>
#include <unistd.h>
#include <unordered_set>
#include <vector>

#include "Netpp/EventLoop.h"
#include "Netpp/EventLoopHandler.h"
#include "Netpp/Exception.h"
#include "Netpp/Logger/Logger.h"
#include "Netpp/TimerScheduler.h"

namespace Netpp::Core
{
using Netpp::Logger::logger;
using Netpp::Logger::LogLevel;

class TimerHandler : public EventLoopHandler, public TimerScheduler
{
public:
  static constexpr const char *TIMER = "timer";

  explicit TimerHandler(EventLoop *loop) : _loop(loop), _fd(-1), _nextTimerToken(1)
  {
    if (!_loop)
    {
      throw EventLoopException(-1, "TimerHandler requires non-null event loop");
    }

    _fd = ::timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    if (_fd < 0)
    {
      auto err = errno;
      logger(TIMER, LogLevel::ERROR, _fd, err, ::strerror(err));
      throw EventLoopException(err, "timerfd_create() failed");
    }

    _loop->add(_fd, this);
    logger(TIMER, LogLevel::TRACE, _fd);
  }

  ~TimerHandler() override
  {
    logger(TIMER, LogLevel::TRACE, _fd);
    if (_fd >= 0)
    {
      _loop->del(_fd);
      ::close(_fd);
    }
  }

  TimerToken scheduleTimer(std::chrono::milliseconds delay, MoveOnlyFunction<void()> callback) override
  {
    if (!callback)
    {
      return INVALID_TIMER;
    }

    const auto token = _nextTimerToken.fetch_add(1, std::memory_order_relaxed);
    const auto now = std::chrono::steady_clock::now();
    const auto deadline = delay.count() <= 0 ? now : now + delay;

    {
      std::scoped_lock lock(_timersMutex);
      _timers.push(std::make_shared<TimerEntry>(TimerEntry{deadline, token, std::move(callback)}));
      rearmTimerLocked();
    }

    return token;
  }

  void cancelTimer(TimerToken token) override
  {
    if (token == INVALID_TIMER)
    {
      return;
    }

    std::scoped_lock lock(_timersMutex);
    _cancelledTimers.emplace(token);
    rearmTimerLocked();
  }

  void handleReading(sock_t fd) override
  {
    uint64_t expirations;
    auto n = ::read(fd, &expirations, sizeof(expirations));
    if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
    {
      logger(TIMER, LogLevel::WARN, "read", fd, errno, ::strerror(errno));
      return;
    }

    processTimers();
  }

  void handleWriting(sock_t) override
  {
  }

  void handleError(sock_t fd) override
  {
    logger(TIMER, LogLevel::ERROR, fd);
  }

private:
  struct TimerEntry
  {
    std::chrono::steady_clock::time_point deadline;
    TimerToken token = INVALID_TIMER;
    MoveOnlyFunction<void()> callback;
  };

  struct TimerEntryCompare
  {
    bool operator()(const std::shared_ptr<TimerEntry> &a, const std::shared_ptr<TimerEntry> &b) const
    {
      return a->deadline > b->deadline;
    }
  };

  void processTimers()
  {
    std::vector<MoveOnlyFunction<void()>> callbacks;
    const auto now = std::chrono::steady_clock::now();

    {
      std::scoped_lock lock(_timersMutex);

      while (!_timers.empty())
      {
        auto timer = _timers.top();
        if (timer->deadline > now)
        {
          break;
        }

        _timers.pop();

        auto cancelled = _cancelledTimers.find(timer->token);
        if (cancelled != _cancelledTimers.end())
        {
          _cancelledTimers.erase(cancelled);
          continue;
        }

        callbacks.emplace_back(std::move(timer->callback));
      }

      rearmTimerLocked();
    }

    for (auto &callback : callbacks)
    {
      if (callback)
      {
        callback();
      }
    }
  }

  void rearmTimerLocked()
  {
    while (!_timers.empty())
    {
      auto cancelled = _cancelledTimers.find(_timers.top()->token);
      if (cancelled == _cancelledTimers.end())
      {
        break;
      }

      _cancelledTimers.erase(cancelled);
      _timers.pop();
    }

    itimerspec spec{};
    if (!_timers.empty())
    {
      auto now = std::chrono::steady_clock::now();
      auto diff = _timers.top()->deadline - now;
      if (diff <= std::chrono::steady_clock::duration::zero())
      {
        diff = std::chrono::nanoseconds(1);
      }

      auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(diff).count();
      spec.it_value.tv_sec = static_cast<time_t>(ns / 1000000000);
      spec.it_value.tv_nsec = static_cast<long>(ns % 1000000000);
    }

    if (::timerfd_settime(_fd, 0, &spec, nullptr) < 0)
    {
      auto err = errno;
      logger(TIMER, LogLevel::ERROR, _fd, err, ::strerror(err));
      throw EventLoopException(err, "timerfd_settime() failed");
    }
  }

  EventLoop *_loop;
  int _fd;
  std::priority_queue<std::shared_ptr<TimerEntry>, std::vector<std::shared_ptr<TimerEntry>>, TimerEntryCompare> _timers;
  std::unordered_set<TimerToken> _cancelledTimers;
  std::mutex _timersMutex;
  std::atomic<TimerToken> _nextTimerToken;
};

} // namespace Netpp::Core
