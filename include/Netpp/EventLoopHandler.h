#pragma once

#include "Netpp/Types.h"

namespace Netpp
{

class EventLoopHandler
{
public:
  virtual void handle(fd_t s, LoopEventType t) = 0;
};

} // namespace Netpp
