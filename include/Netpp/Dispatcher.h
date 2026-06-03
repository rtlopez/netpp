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
  
  virtual void onConnect(ConnectionPtr conn) = 0;
  virtual void onDisconnect(ConnectionPtr conn) = 0;
  virtual void send(ConnectionPtr conn, DataEvent data) = 0;

  virtual std::queue<DataEvent> &getSendQueue(ConnectionPtr conn) = 0;

  virtual sock_t getNotifyFd() const { return -1; }
  virtual std::vector<sock_t> drainPendingWrites() { return {}; }
  virtual void postRecv(MoveOnlyFunction<void()> task) { task(); }
  virtual void postForConnection(ConnectionPtr, MoveOnlyFunction<void()> task) { task(); }
  virtual std::unique_lock<std::mutex> lockSend() { return {}; }
};

} // namespace Netpp
