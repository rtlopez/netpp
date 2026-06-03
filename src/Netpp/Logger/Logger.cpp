#include <array>

#include "Netpp/Logger/Logger.h"

namespace
{
static Netpp::Logger::Logger instance;
constexpr std::array<std::string_view, Netpp::Logger::FATAL + 1> logLevelNames = {"TRACE", "DEBUG", "INFO",
                                                                                  "WARN",  "ERROR", "FATAL"};

constexpr bool iequals(std::string_view lhs, std::string_view rhs)
{
  if (lhs.size() != rhs.size())
  {
    return false;
  }

  for (size_t i = 0; i < lhs.size(); ++i)
  {
    const char a = lhs[i] >= 'A' && lhs[i] <= 'Z' ? static_cast<char>(lhs[i] - 'A' + 'a') : lhs[i];
    const char b = rhs[i] >= 'A' && rhs[i] <= 'Z' ? static_cast<char>(rhs[i] - 'A' + 'a') : rhs[i];
    if (a != b)
    {
      return false;
    }
  }

  return true;
}
} // namespace

namespace Netpp::Logger
{

const std::string_view logLevelToName(LogLevel level)
{
  const size_t index = static_cast<size_t>(level);
  if (index >= logLevelNames.size())
  {
    return "INFO!";
  }
  return logLevelNames[index];
}

std::optional<LogLevel> logLevelFromName(std::string_view name)
{
  for (size_t i = 0; i < logLevelNames.size(); ++i)
  {
    if (iequals(name, logLevelNames[i]))
    {
      return static_cast<LogLevel>(i);
    }
  }

  return std::nullopt;
}

LogEntry::~LogEntry()
{
  Logger::getInstance()->write(*this);
}

Logger *Logger::getInstance()
{
  return &instance;
}

} // namespace Netpp::Logger
