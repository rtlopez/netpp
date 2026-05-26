#pragma once

#include "Connection.h"
#include "DataEvent.h"

namespace Netpp
{

class Protocol
{
public:
  virtual void onConnect(ConnectionPtr conn) = 0;
  virtual void onReceive(DataEvent data) = 0;
  virtual void onDisconnect(ConnectionPtr conn) = 0;
};

} // namespace Netpp
