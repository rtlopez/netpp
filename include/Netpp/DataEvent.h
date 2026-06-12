#pragma once

#include <cstdint>
#include <vector>

namespace Netpp
{

enum EventType
{
  DATA = 0,
  CONNECT = 1,
  DISCONNECT = 2,
  ERROR = 3,
  EVENT_TYPE_COUNT = 4,
};

struct DataEvent
{
  using Buffer = std::vector<uint8_t>;

  Buffer buffer = Buffer{};
  EventType eventType = DATA;
  size_t sent = 0;
};

} // namespace Netpp
