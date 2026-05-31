#pragma once

#include <mutex>
#include <queue>
#include <vector>

#include "MoveOnlyFunction.h"
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

  virtual std::queue<DataEvent> &getSendQueue(sock_t s) = 0;

  virtual sock_t getNotifyFd() const { return -1; }
  virtual std::vector<sock_t> drainPendingWrites() { return {}; }
  virtual void postRecv(MoveOnlyFunction<void()> task) { task(); }
  virtual std::unique_lock<std::mutex> lockSend(sock_t) { return {}; }
};

} // namespace Netpp
