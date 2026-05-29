#pragma once

#include <unordered_set>
#include <queue>

#include "Sender.h"
#include "Socket.h"

namespace Netpp
{

class Protocol;

class Dispatcher : public Sender
{
public:
  virtual ~Dispatcher() = default;

  virtual void onConnect(sock_t s) = 0;
  virtual void onDisconnect(sock_t s) = 0;
  virtual void onSendDone(sock_t s) = 0;

  virtual std::queue<DataEvent> &getSendQueue(sock_t s) = 0;
  virtual std::unordered_set<sock_t> getPendingResponses() = 0;
};

} // namespace Netpp
