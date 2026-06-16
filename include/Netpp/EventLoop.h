#pragma once

#include <functional>

#include "EventLoopHandler.h"
#include "Socket.h"

namespace Netpp
{

class EventLoop
{
public:
  using StopCallback = std::function<void()>;

  virtual void add(sock_t fd, EventLoopHandler *handler, bool refCount = true) = 0;
  virtual void del(sock_t fd, bool refCount = true) = 0;
  virtual void mod(sock_t fd, bool write) = 0;
  virtual StopCallback getStopCallback() = 0;
  virtual void run() = 0;
};

} // namespace Netpp
