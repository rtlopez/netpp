#pragma once

#include <string>

#include "Netpp/EventLoop.h"
#include "Netpp/Logger/Logger.h"
#include "Netpp/MoveOnlyFunction.h"

namespace Netpp::Core
{
using Netpp::Logger::logger;
using Netpp::Logger::LogLevel;

class StdinHandler : public EventLoopHandler
{
public:
  using RecieverCallback = MoveOnlyFunction<void(const std::string &)>;

  static constexpr const char *STDIN = "stdin";

  StdinHandler(EventLoop *loop, RecieverCallback receiver) : _loop(loop), _receiver(std::move(receiver))
  {
    // add stdin fd to event loop
    _loop->add(STDIN_FILENO, this);
  }

  void handle(fd_t s, LoopEventType t) override
  {
    switch (t)
    {
    case LoopEventType::READ:
      handleReading(s);
      break;
    case LoopEventType::ERROR:
      handleError(s);
      break;
    default:
      break;
    }
  }

  void handleReading(fd_t s)
  {
    // read a line from stdin and send to receiver callback
    std::string line;
    if (!std::getline(std::cin, line))
    {
      logger(STDIN, LogLevel::DEBUG, s, "stopping");
      _loop->stop();
      return;
    }
    line += '\n';
    _receiver(line);
  }

  void handleError(fd_t s)
  {
    // log error and stop loop
    logger(STDIN, LogLevel::DEBUG, s, "error");
    _loop->stop();
  }

private:
  EventLoop *_loop = nullptr;
  RecieverCallback _receiver = {};
};

} // namespace Netpp::Core