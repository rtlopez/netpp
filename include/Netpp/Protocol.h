#pragma once

#include "Connection.h"

namespace Netpp
{

class Protocol
{
public:
  enum Status
  {
    OK,
    ERROR,
    CLOSE,
  };
  virtual Status onConnect(ConnectionPtr conn) = 0;
  virtual Status onReceive(ConnectionPtr conn) = 0;
  virtual Status onDisconnect(ConnectionPtr conn) = 0;
};

} // namespace Netpp
