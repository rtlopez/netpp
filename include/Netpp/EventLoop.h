#pragma once

#include "EventLoopHandler.h"
#include "Socket.h"

namespace Netpp
{

class EventLoop
{
public:
  virtual void add(sock_t fd, EventLoopHandler *handler) = 0;
  virtual void del(sock_t fd) = 0;
  virtual void run() = 0;
  virtual void stop() = 0;
};

} // namespace Netpp
