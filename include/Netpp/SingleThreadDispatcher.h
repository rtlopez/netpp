#pragma once

#include <queue>
#include <unordered_map>
#include <unordered_set>

#include "Dispatcher.h"
#include "NetppDebug.h"

namespace Netpp
{

class SingleThreadDispatcher : public Dispatcher
{
public:
  void send(DataEvent data) override
  {
    auto s = data.conn->getId();
    getSendQueue(s).push(std::move(data));
    _pendingResponses.insert(s);
  }

  void onConnect(sock_t s) override
  {
    debug("SingleThreadDispatcher::onConnect", s);
    _sendQueue.emplace(s, std::queue<DataEvent>{});
  }

  void onDisconnect(sock_t s) override
  {
    debug("SingleThreadDispatcher::onDisconnect", s);
    _sendQueue.erase(s);
    _pendingResponses.erase(s);
  }

  void onSendDone(sock_t s) override
  {
    _pendingResponses.erase(s);
  }

  std::queue<DataEvent> &getSendQueue(sock_t s) override
  {
    return _sendQueue.at(s);
  }

  std::unordered_set<sock_t> getPendingResponses() override
  {
    return _pendingResponses;
  }

private:
  std::unordered_map<sock_t, std::queue<DataEvent>> _sendQueue;
  std::unordered_set<sock_t> _pendingResponses;
};

} // namespace Netpp
