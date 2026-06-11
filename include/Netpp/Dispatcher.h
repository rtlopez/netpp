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

inline const char *to_string(DrainResult r)
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

  // join worker threads; must be called while the objects tasks reference are still alive
  virtual void stop()
  {
  }

  // post task to connection queue then to worker queue, ensures task is executed in connection strand
  virtual void post(ConnectionPtr, MoveOnlyFunction<void()> task) = 0;

  // post task to worker queue
  virtual void post(MoveOnlyFunction<void()> task) = 0;

  // schedule send of data to connection from worker
  virtual void send(ConnectionPtr conn, DataEvent data) = 0;

  // schedule send of data to connection from generator
  virtual void send(ConnectionPtr conn, MoveOnlyFunction<DataEvent(void)> generator) = 0;

  // drain connection send queue
  virtual DrainResult drain(ConnectionPtr conn, std::function<bool(ConnectionPtr, DataEvent &)> sendFunc) = 0;

  // run generator to produce and send next chunk of data
  virtual void runGenerator(ConnectionPtr conn) = 0;

protected:
  EventLoop *_loop;
};

} // namespace Netpp
