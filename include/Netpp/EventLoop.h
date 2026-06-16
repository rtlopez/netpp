#pragma once

#include "Netpp/EventLoopHandler.h"
#include "Netpp/Types.h"

namespace Netpp
{

class EventLoop
{
public:
  virtual void add(fd_t fd, EventLoopHandler *handler, bool refCount = true) = 0;
  virtual void del(fd_t fd, bool refCount = true) = 0;
  virtual void mod(fd_t fd, bool write) = 0;
  virtual void stop() = 0;
  virtual void run() = 0;
};

} // namespace Netpp
