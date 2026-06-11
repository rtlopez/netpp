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

class LogEntry
{
public:
  LogEntry(std::string_view channel, LogLevel level, std::source_location location,
           std::chrono::system_clock::time_point timestamp, pid_t threadId)
      : _channel(channel), _level(level), _location(location), _timestamp(timestamp), _threadId(threadId)
  {
  }

  LogEntry(const LogEntry &) = delete;
  LogEntry &operator=(const LogEntry &) = delete;

  LogEntry(LogEntry &&) = default;
  LogEntry &operator=(LogEntry &&) = default;

  ~LogEntry() = default;

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

class LogFormatter
{
public:
  virtual ~LogFormatter() = default;
  virtual std::string format(const LogEntry &entry) = 0;
};

class LogWriter
{
public:
  virtual ~LogWriter() = default;
  virtual void write(std::string_view message) = 0;
};

class LogWriterConsole : public LogWriter
{
public:
  LogWriterConsole()
  {
    // turn off io sync
    std::ios_base::sync_with_stdio(false);
    // untie cin from cout
    std::cin.tie(nullptr);
  }

  void write(std::string_view message) override
  {
    // fastest exception-free block memory write to stdout
    std::scoped_lock lock(_mutex);
    std::cout.write(message.data(), message.size());
    std::cout.flush();
  }

private:
  std::mutex _mutex;
};

class LogFormatterSimple : public LogFormatter
{
public:
  std::string format(const LogEntry &entry) override
  {
    std::ostringstream ss;
    write(ss, entry);
    return std::move(ss).str();
  }

  void write(std::ostringstream &ss, const LogEntry &entry)
  {
    write(ss, entry.getTimestamp());
    write(ss, entry.getThreadId());
    write(ss, entry.getLevel());
    write(ss, entry.getChannel());
    write(ss, entry.getLocation());
    write(ss, entry.str());
    ss << "\n";
  }

  void write(std::ostringstream &ss, std::chrono::system_clock::time_point timestamp)
  {
    auto time_t_now = std::chrono::system_clock::to_time_t(timestamp);
    auto us = std::chrono::duration_cast<std::chrono::microseconds>(timestamp.time_since_epoch()) % 1000000;
    std::tm tm_buf;
    ::localtime_r(&time_t_now, &tm_buf);
    ss << std::put_time(&tm_buf, "%Y-%m-%d %H:%M:%S") << "." << std::setfill('0') << std::setw(6) << us.count();
  }

  void write(std::ostringstream &ss, LogLevel level)
  {
    ss << " " << logLevelToName(level);
  }

  void write(std::ostringstream &ss, std::source_location location)
  {
    ss << " " << extractFileName(location.file_name()) << ":" << location.line() << ":"
       << extractFunctionName(location.function_name());
  }

  template <typename T>
  void write(std::ostringstream &ss, const T &message)
  {
    ss << " " << message;
  }
};

class LogHandler
{
public:
  virtual ~LogHandler() = default;
  virtual void handle(const LogEntry &entry) = 0;
};

class LogHandlerSimple : public LogHandler
{
public:
  LogHandlerSimple(std::unique_ptr<LogFormatter> formatter, std::unique_ptr<LogWriter> writer)
      : _formatter(std::move(formatter)), _writer(std::move(writer))
  {
  }

  void handle(const LogEntry &entry) override
  {
    _writer->write(_formatter->format(entry));
  }

private:
  std::unique_ptr<LogFormatter> _formatter;
  std::unique_ptr<LogWriter> _writer;
};

class Logger
{
public:
  Logger() = default;
  ~Logger() = default;

  static Logger *getInstance();

  void write(const LogEntry &entry)
  {
    if (entry.getLevel() >= _level)
    {
      for (auto &handler : _handlers)
      {
        handler->handle(entry);
      }
    }
  }

  void addHandler(std::unique_ptr<LogHandler> handler)
  {
    _handlers.push_back(std::move(handler));
  }

  void setLevel(LogLevel level)
  {
    _level = level;
  }

private:
  LogLevel _level = LogLevel::INFO;
  std::vector<std::unique_ptr<LogHandler>> _handlers;
};

inline LogEntry logger(std::string_view channel, LogLevel level,
                       std::source_location loc = std::source_location::current())
{
  return LogEntry{channel, level, loc, std::chrono::system_clock::now(), ::gettid()};
}

template <typename... Args>
inline void logger(std::string_view channel, LogLevel level, Args... rest)
{
  auto entry = logger(channel, level);
  entry.log(rest...);
  Logger::getInstance()->write(std::move(entry));
}

} // namespace Netpp::Logger
