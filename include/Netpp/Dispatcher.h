#pragma once

#include <vector>

#include "Connection.h"
#include "DataEvent.h"
#include "MoveOnlyFunction.h"
#include "Socket.h"

namespace Netpp
{

class Protocol;

class Dispatcher
{
public:
  virtual ~Dispatcher() = default;

  virtual void send(ConnectionPtr conn, DataEvent data) = 0;

  virtual sock_t getNotifyFd() const
  {
    return -1;
  }

  virtual std::vector<sock_t> drainPendingWrites()
  {
    return {};
  }

  virtual void postRecv(MoveOnlyFunction<void()> task)
  {
    task();
  }

  virtual void postForConnection(ConnectionPtr, MoveOnlyFunction<void()> task)
  {
    task();
  }
};

} // namespace Netpp
