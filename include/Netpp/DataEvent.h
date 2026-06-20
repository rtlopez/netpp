#pragma once

#include <cstdint>
#include <vector>

namespace Netpp
{

enum class EventType
{
  DATA = 0,
  CONNECT = 1,
  DISCONNECT = 2,
  ERROR = 3,
  TIMEOUT = 4,
  RESOLVED = 5,
  DONE = 6,
  EVENT_TYPE_COUNT = 7,
};

struct DataEvent
{
  using Buffer = std::vector<uint8_t>;

  Buffer buffer{};
  EventType eventType{EventType::DATA};
  size_t sent{};
};

} // namespace Netpp
