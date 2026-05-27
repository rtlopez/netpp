#pragma once

#include <functional>

#include "Sender.h"
#include "Socket.h"

namespace Netpp
{

class Protocol;

class Dispatcher : public Sender
{
public:
  virtual ~Dispatcher() = default;
  virtual void post(DataEvent data, Protocol *target) = 0;
  virtual void drain(std::function<void(sock_t)> handleClose) = 0;
};

} // namespace Netpp
