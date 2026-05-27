#pragma once

#include <vector>

#include "Connection.h"

namespace Netpp
{

struct DataEvent
{
  using Buffer = std::vector<uint8_t>;
  ConnectionPtr conn;
  Buffer data;
};

} // namespace Netpp
