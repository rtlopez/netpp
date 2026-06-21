#pragma once

#include <cstdio>
#include <memory>

#include "Netpp/DataEvent.h"
#include "Netpp/MoveOnlyFunction.h"

namespace Netpp::Http
{

class ChunkedEncoder
{
public:
  ChunkedEncoder(MoveOnlyFunction<DataEvent(void)> inner) : _inner(std::move(inner))
  {
  }

  ChunkedEncoder(const ChunkedEncoder &) = delete;
  ChunkedEncoder &operator=(const ChunkedEncoder &) = delete;
  ChunkedEncoder(ChunkedEncoder &&) = default;
  ChunkedEncoder &operator=(ChunkedEncoder &&) = default;

  DataEvent operator()()
  {
    auto event = _inner();

    if (event.eventType != EventType::DATA && event.eventType != EventType::DONE)
    {
      return event;
    }

    DataEvent::Buffer result;
    if (!event.buffer.empty())
    {
      auto hex = toHex(event.buffer.size());
      result.reserve(hex.size() + 2 + event.buffer.size() + 2 + (event.eventType == EventType::DONE ? 5 : 0));
      result.insert(result.end(), hex.begin(), hex.end());
      result.push_back('\r');
      result.push_back('\n');
      result.insert(result.end(), event.buffer.begin(), event.buffer.end());
      result.push_back('\r');
      result.push_back('\n');
    }

    if (event.eventType == EventType::DONE)
    {
      static constexpr char terminator[] = "0\r\n\r\n";
      result.insert(result.end(), terminator, terminator + 5);
    }

    return {.buffer = std::move(result), .eventType = event.eventType};
  }

  static MoveOnlyFunction<DataEvent(void)> wrap(MoveOnlyFunction<DataEvent(void)> inner)
  {
    auto enc = std::make_unique<ChunkedEncoder>(std::move(inner));
    return [enc = std::move(enc)]() { return (*enc)(); };
  }

private:
  static std::string toHex(size_t n)
  {
    char buf[17];
    std::snprintf(buf, sizeof(buf), "%zx", n);
    return buf;
  }

  MoveOnlyFunction<DataEvent(void)> _inner;
};

} // namespace Netpp::Http
