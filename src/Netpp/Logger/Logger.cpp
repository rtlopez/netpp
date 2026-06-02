#include "Netpp/Logger/Logger.h"

namespace
{
static Netpp::Logger::Logger instance;
}

namespace Netpp::Logger
{

LogEntry::~LogEntry()
{
  Logger::getInstance()->write(*this);
}

Logger *Logger::getInstance()
{
  return &instance;
}

} // namespace Netpp::Logger
