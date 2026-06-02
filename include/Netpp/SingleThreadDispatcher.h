#pragma once

#include <queue>
#include <unordered_map>

#include "Dispatcher.h"
#include "Netpp/Logger/Logger.h"

namespace Netpp
{

using Netpp::Logger::logger;
using Netpp::Logger::LogLevel;
static const char *DISPATCH = "dispatch";

class SingleThreadDispatcher : public Dispatcher
{
public:
  void send(DataEvent data) override
  {
    auto s = data.conn->getId();
    getSendQueue(s).push(std::move(data));
  }

  void onConnect(sock_t s) override
  {
    logger(DISPATCH, LogLevel::DEBUG).log(s);
    _sendQueue.emplace(s, std::queue<DataEvent>{});
  }

  void onDisconnect(sock_t s) override
  {
    logger(DISPATCH, LogLevel::DEBUG).log(s);
    _sendQueue.erase(s);
  }

  std::queue<DataEvent> &getSendQueue(sock_t s) override
  {
    return _sendQueue.at(s);
  }

private:
  std::unordered_map<sock_t, std::queue<DataEvent>> _sendQueue;
};

} // namespace Netpp
