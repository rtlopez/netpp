#include <array>
#include <cctype>

#include "Netpp/Logger/Logger.h"

namespace
{
static Netpp::Logger::Logger instance;
constexpr std::array<std::string_view, Netpp::Logger::FATAL + 1> logLevelNames = {"TRACE", "DEBUG", "INFO",
                                                                                  "WARN",  "ERROR", "FATAL"};

constexpr bool logLevelEquals(std::string_view lhs, std::string_view rhs)
{
  if (lhs.size() != rhs.size())
  {
    return false;
  }

  for (size_t i = 0; i < lhs.size(); ++i)
  {
    if (std::toupper(lhs[i]) != std::toupper(rhs[i]))
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
    if (logLevelEquals(name, logLevelNames[i]))
    {
      return static_cast<LogLevel>(i);
    }
  }

  return std::nullopt;
}

Logger *Logger::getInstance()
{
  return &instance;
}

} // namespace Netpp::Logger
