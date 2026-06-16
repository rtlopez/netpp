#pragma once

#include "Netpp/Types.h"

namespace Netpp
{

class EventLoopHandler
{
public:
  virtual void handleReading(fd_t s) = 0;
  virtual void handleWriting(fd_t s) = 0;
  virtual void handleError(fd_t s) = 0;
};

} // namespace Netpp
