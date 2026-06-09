#pragma once

#include "Dispatcher.h"

namespace Netpp
{

class SingleThreadDispatcher : public Dispatcher
{
public:
  SingleThreadDispatcher(EventLoop *loop) : Dispatcher(loop)
  {
  }

  void send(ConnectionPtr conn, DataEvent data) override
  {
    conn->sendQueue().push(std::move(data));
  }

  DrainResult drainSendQueue(ConnectionPtr conn, std::function<DrainResult(ConnectionPtr)> drainFunc) override
  {
    return drainFunc(conn);
  }
};

} // namespace Netpp
