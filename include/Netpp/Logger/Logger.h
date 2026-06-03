#pragma once

#include <chrono>
#include <iostream>
#include <mutex>
#include <optional>
#include <source_location>
#include <sstream>
#include <string>
#include <string_view>
#include <unistd.h>

namespace Netpp::Logger
{

enum LogLevel : size_t
{
  TRACE = 0,
  DEBUG = 1,
  INFO = 2,
  WARN = 3,
  ERROR = 4,
  FATAL = 5,
};

const std::string_view logLevelToName(LogLevel level);
std::optional<LogLevel> logLevelFromName(std::string_view name);

inline std::string_view extractFileName(std::string_view path)
{
  auto pos = path.find_last_of("/\\");
  return pos == std::string_view::npos ? path : path.substr(pos + 1);
}

inline std::string_view extractFunctionName(std::string_view name)
{
  auto paren = name.find('(');
  if (paren != std::string_view::npos)
  {
    name = name.substr(0, paren);
  }
  auto space = name.rfind(' ');
  if (space != std::string_view::npos)
  {
    name = name.substr(space + 1);
  }
  auto colon = name.rfind(':');
  if (colon != std::string_view::npos)
  {
    name = name.substr(colon + 1);
  }
  return name;
}

class Logger;

class LogEntry
{
public:
  LogEntry(std::string_view channel, LogLevel level, std::source_location location,
           std::chrono::system_clock::time_point timestamp, pid_t threadId)
      : _channel(channel), _level(level), _location(location), _timestamp(timestamp), _threadId(threadId)
  {
  }

  ~LogEntry();

  template <typename T>
  void log(T value)
  {
    _stream << value;
  }

  template <typename T, typename... Args>
  void log(T first, Args... rest)
  {
    _stream << first << " ";
    log(rest...);
  }

  std::string_view getChannel() const
  {
    return _channel;
  }

  LogLevel getLevel() const
  {
    return _level;
  }

  std::source_location getLocation() const
  {
    return _location;
  }

  std::chrono::system_clock::time_point getTimestamp() const
  {
    return _timestamp;
  }

  pid_t getThreadId() const
  {
    return _threadId;
  }

  std::string str() const
  {
    return _stream.str();
  }

private:
  std::string_view _channel;
  LogLevel _level;
  std::source_location _location;
  std::chrono::system_clock::time_point _timestamp;
  pid_t _threadId;
  std::ostringstream _stream;
};

class Logger
{
public:
  Logger() = default;
  ~Logger() = default;

  static Logger *getInstance();

  void setLevel(LogLevel level)
  {
    _level = level;
  }

  void write(const LogEntry &entry)
  {
    if (entry.getLevel() < _level)
    {
      return;
    }
    std::scoped_lock lock(_mutex);
    write(entry.getTimestamp());
    write(entry.getThreadId());
    write(entry.getLevel());
    write(entry.getChannel());
    write(entry.getLocation());
    write(entry.str());
    std::cout << std::endl;
  }

private:
  void write(std::chrono::system_clock::time_point timestamp)
  {
    auto time_t_now = std::chrono::system_clock::to_time_t(timestamp);
    auto us = std::chrono::duration_cast<std::chrono::microseconds>(timestamp.time_since_epoch()) % 1000000;
    std::tm tm_buf;
    ::localtime_r(&time_t_now, &tm_buf);
    std::cout << std::put_time(&tm_buf, "%Y-%m-%d %H:%M:%S") << "." << std::setfill('0') << std::setw(6) << us.count();
  }

  void write(LogLevel level)
  {
    std::cout << " " << logLevelToName(level);
  }

  void write(std::source_location location)
  {
    std::cout << " " << extractFileName(location.file_name()) << ":" << location.line() << ":"
              << extractFunctionName(location.function_name());
  }

  template <typename T>
  void write(const T &message)
  {
    std::cout << " " << message;
  }

  std::mutex _mutex;
  LogLevel _level = LogLevel::INFO;
};

inline LogEntry logger(std::string_view channel, LogLevel level,
                       std::source_location loc = std::source_location::current())
{
  return LogEntry{channel, level, loc, std::chrono::system_clock::now(), ::gettid()};
}

} // namespace Netpp::Logger
