#pragma once

#include "Connection.h"
#include "DataEvent.h"
#include "MoveOnlyFunction.h"

namespace Netpp
{

class TransportHandler
{
public:
  virtual ~TransportHandler() = default;
  virtual void send(ConnectionPtr conn, DataEvent data) = 0;
  virtual void send(ConnectionPtr conn, MoveOnlyFunction<DataEvent(void)> generator) = 0;
};

} // namespace Netpp
