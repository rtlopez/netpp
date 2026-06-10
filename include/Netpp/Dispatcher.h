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

inline const char* to_string(DrainResult r)
{
  switch (r)
  {
  case DrainResult::Done:
    return "Done";
  case DrainResult::Partial:
    return "Partial";
  case DrainResult::Close:
    return "Close";
  default:
    return "Unknown";
  }
}

class Dispatcher
{
public:
  Dispatcher(EventLoop *loop) : _loop(loop)
  {
  }

  virtual ~Dispatcher() = default;

  virtual void send(ConnectionPtr conn, DataEvent data) = 0;

  virtual void postRecv(MoveOnlyFunction<void()> task) = 0;

  virtual void postForConnection(ConnectionPtr, MoveOnlyFunction<void()> task) = 0;

  virtual DrainResult drainSendQueue(ConnectionPtr conn, std::function<DrainResult(ConnectionPtr)> drainFunc) = 0;

protected:
  EventLoop *_loop;
};

} // namespace Netpp
