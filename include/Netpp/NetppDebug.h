#pragma once

#include <iostream>
#include <chrono>
#include <iomanip>
#include <ctime>

#if 1
namespace
{

inline void debug_timestamp()
{
  auto now = std::chrono::system_clock::now();
  auto time_t_now = std::chrono::system_clock::to_time_t(now);
  auto us = std::chrono::duration_cast<std::chrono::microseconds>(
      now.time_since_epoch()) % 1000000;
  std::tm tm_buf;
  localtime_r(&time_t_now, &tm_buf);
  std::cout << std::put_time(&tm_buf, "%Y-%m-%d %H:%M:%S")
            << "." << std::setfill('0') << std::setw(6) << us.count() << " ";
}

template <typename T>
void debug_impl(T last)
{
  std::cout << last << "\n";
}

template <typename T, typename... Args>
void debug_impl(T first, Args... rest)
{
  std::cout << first << " ";
  debug_impl(rest...);
}

template <typename... Args>
void debug(Args... args)
{
  debug_timestamp();
  debug_impl(args...);
}

} // namespace
#else
#define debug(...)
#endif
