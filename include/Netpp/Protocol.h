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
    _handlers[eventType] = std::move(handler);
  }

  // Main event dispatch - calls registered handlers or can be overridden
  virtual void handle(ConnectionPtr conn, DataEvent data)
  {
    if (data.eventType >= EVENT_TYPE_COUNT)
    {
      logger("protocol", LogLevel::ERROR, data.eventType, "invalid");
      return;
    }

    if (hasHandler(data.eventType))
    {
      _handlers[data.eventType](conn, data);
    }
  }

  bool hasHandler(EventType eventType) const
  {
    return eventType < EVENT_TYPE_COUNT && _handlers[eventType] != nullptr;
  }

private:
  std::array<EventHandlerCallback, EVENT_TYPE_COUNT> _handlers;
};

} // namespace Netpp
