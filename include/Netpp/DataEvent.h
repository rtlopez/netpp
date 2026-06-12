#pragma once

#include <cstdint>
#include <vector>

namespace Netpp
{

struct DataEvent
{
  using Buffer = std::vector<uint8_t>;

  Buffer buffer;
  bool close = false;
  bool connect = false;
  bool disconnect = false;
  size_t sent = 0;
};

} // namespace Netpp
