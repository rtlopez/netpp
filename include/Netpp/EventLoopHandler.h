#pragma once

#include "Socket.h"

namespace Netpp
{

class EventLoopHandler
{
public:
  virtual void handleReading(sock_t s) = 0;
  virtual void handleWriting(sock_t s) = 0;
  virtual void handleError(sock_t s) = 0;
};

} // namespace Netpp
