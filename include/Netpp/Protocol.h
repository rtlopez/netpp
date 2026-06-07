#pragma once

#include "Connection.h"
#include "DataEvent.h"

namespace Netpp
{

class Protocol
{
public:
  virtual ~Protocol() = default;

  virtual void onReceive(ConnectionPtr conn, DataEvent data) = 0;
};

} // namespace Netpp
