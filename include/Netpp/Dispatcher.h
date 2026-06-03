#pragma once

#include <mutex>
#include <vector>

#include "Connection.h"
#include "MoveOnlyFunction.h"
#include "Socket.h"
#include "DataEvent.h"

namespace Netpp
{

class Protocol;

class Dispatcher
{
public:
  virtual ~Dispatcher() = default;
  
  virtual void onConnect(sock_t s) = 0;
  virtual void onDisconnect(sock_t s) = 0;
  virtual void send(sock_t s, DataEvent data) = 0;

  virtual std::queue<DataEvent> &getSendQueue(sock_t s) = 0;

  virtual sock_t getNotifyFd() const { return -1; }
  virtual std::vector<sock_t> drainPendingWrites() { return {}; }
  virtual void postRecv(MoveOnlyFunction<void()> task) { task(); }
  virtual void postForConnection(ConnectionPtr, MoveOnlyFunction<void()> task) { task(); }
  virtual std::unique_lock<std::mutex> lockSend(sock_t) { return {}; }
};

} // namespace Netpp
