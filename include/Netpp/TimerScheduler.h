#pragma once

#include <chrono>
#include <cstdint>

#include "MoveOnlyFunction.h"

namespace Netpp
{

class TimerScheduler
{
public:
  using TimerToken = uint64_t;
  static constexpr TimerToken INVALID_TIMER = 0;

  virtual ~TimerScheduler() = default;

  virtual TimerToken scheduleTimer(std::chrono::milliseconds delay, MoveOnlyFunction<void()> callback) = 0;
  virtual void cancelTimer(TimerToken token) = 0;
};

} // namespace Netpp