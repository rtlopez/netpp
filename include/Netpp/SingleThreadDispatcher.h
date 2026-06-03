#pragma once

#include "Dispatcher.h"

namespace Netpp
{

class SingleThreadDispatcher : public Dispatcher
{
public:
  void send(ConnectionPtr conn, DataEvent data) override
  {
    conn->sendQueue().push(std::move(data));
  }
};

} // namespace Netpp
