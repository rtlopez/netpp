#pragma once

#include <functional>
#include <string>

#include "Netpp/EventLoop.h"
#include "Netpp/Logger/Logger.h"
#include "Netpp/LoopControlHandler.h"

namespace Netpp::Core
{

class StdinHandler : public Netpp::EventLoopHandler
{
public:
  static constexpr const char *STDIN = "stdin";

  StdinHandler(Netpp::EventLoop *loop, Netpp::LoopControlHandler *loopControl,
               std::function<void(const std::string &)> receiver)
      : _loop(loop), _loopControl(loopControl), _receiver(receiver)
  {
    // add stdin fd to event loop
    _loop->add(STDIN_FILENO, this);
  }

  void handleReading(Netpp::sock_t s) override
  {
    // read a line from stdin and send to receiver callback
    std::string line;
    if (!std::getline(std::cin, line))
    {
      Netpp::Logger::logger(STDIN, Netpp::Logger::LogLevel::DEBUG, s, "stopping");
      _loopControl->stop();
      return;
    }
    line += '\n';
    _receiver(line);
  }

  void handleWriting(Netpp::sock_t) override
  {
    // not used for stdin
  }

  void handleError(Netpp::sock_t s) override
  {
    // log error and stop loop
    Netpp::Logger::logger(STDIN, Netpp::Logger::LogLevel::DEBUG, s, "error");
    _loopControl->stop();
  }

private:
  Netpp::EventLoop *_loop;
  Netpp::LoopControlHandler *_loopControl;
  std::function<void(const std::string &)> _receiver;
};

} // namespace Netpp::Core