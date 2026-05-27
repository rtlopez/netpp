#pragma once

#include "DataEvent.h"

namespace Netpp
{

class Sender
{
public:
  virtual ~Sender() = default;
  virtual void send(DataEvent data) = 0;
};

} // namespace Netpp
