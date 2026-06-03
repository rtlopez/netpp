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
  void send(ConnectionPtr conn, DataEvent data) override
  {
    getSendQueue(conn).push(std::move(data));
  }

  void onConnect(ConnectionPtr conn) override
  {
    logger(DISPATCH, LogLevel::DEBUG).log(conn->getId());
    _sendQueues.emplace(conn->getId(), std::queue<DataEvent>{});
  }

  void onDisconnect(ConnectionPtr conn) override
  {
    logger(DISPATCH, LogLevel::DEBUG).log(conn->getId());
    _sendQueues.erase(conn->getId());
  }

  std::queue<DataEvent> &getSendQueue(ConnectionPtr conn) override
  {
    return _sendQueues.at(conn->getId());
  }

private:
  std::unordered_map<sock_t, std::queue<DataEvent>> _sendQueues;
};

} // namespace Netpp
