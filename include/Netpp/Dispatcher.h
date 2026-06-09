#pragma once

#include <functional>

#include "Connection.h"
#include "DataEvent.h"
#include "EventLoop.h"
#include "MoveOnlyFunction.h"

namespace Netpp
{

class Protocol;

enum DrainResult
{
  Done,
  Partial,
  Close
};

class Dispatcher
{
public:
  Dispatcher(EventLoop *loop) : _loop(loop)
  {
  }

  virtual ~Dispatcher() = default;

  virtual void send(ConnectionPtr conn, DataEvent data) = 0;

  virtual void postRecv(MoveOnlyFunction<void()> task)
  {
    task();
  }

  virtual void postForConnection(ConnectionPtr, MoveOnlyFunction<void()> task)
  {
    task();
  }

  virtual DrainResult drainSendQueue(ConnectionPtr conn, std::function<DrainResult(ConnectionPtr)> drainFunc) = 0;

protected:
  EventLoop *_loop;
};

} // namespace Netpp
