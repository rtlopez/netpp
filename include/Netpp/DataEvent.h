#pragma once

#include <vector>

#include "Connection.h"

namespace Netpp
{

struct DataEvent
{
  ConnectionPtr conn;
  std::vector<uint8_t> data;
};

} // namespace Netpp
