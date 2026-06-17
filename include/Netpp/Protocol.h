#pragma once

#include <array>
#include <functional>

#include "Connection.h"
#include "DataEvent.h"

namespace Netpp
{

class Protocol
{
public:
  using EventHandlerCallback = std::function<void(ConnectionPtr, const DataEvent &)>;

  Protocol() = default;
  virtual ~Protocol() = default;

  // Register a handler for an event: "connect", "disconnect", "data"
  void on(EventType eventType, EventHandlerCallback handler)
  {
    _handlers[static_cast<size_t>(eventType)] = std::move(handler);
  }

  // Main event dispatch - calls registered handlers or can be overridden
  virtual void handle(ConnectionPtr conn, DataEvent data)
  {
    if (data.eventType >= EventType::EVENT_TYPE_COUNT)
    {
      logger("protocol", LogLevel::ERROR, (size_t)data.eventType, "invalid");
      return;
    }

    if (hasHandler(data.eventType))
    {
      _handlers[static_cast<size_t>(data.eventType)](conn, data);
    }
  }

  bool hasHandler(EventType eventType) const
  {
    return eventType < EventType::EVENT_TYPE_COUNT && _handlers[static_cast<size_t>(eventType)] != nullptr;
  }

private:
  std::array<EventHandlerCallback, static_cast<size_t>(EventType::EVENT_TYPE_COUNT)> _handlers;
};

} // namespace Netpp
