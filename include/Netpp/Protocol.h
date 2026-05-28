#pragma once

#include "Connection.h"
#include "DataEvent.h"
#include "Sender.h"

namespace Netpp
{

class Protocol
{
public:
  Protocol(Sender *sender) : _sender(sender)
  {
  }

  virtual ~Protocol() = default;

  virtual void onConnect(ConnectionPtr conn) = 0;
  virtual void onReceive(DataEvent data) = 0;
  virtual void onDisconnect(ConnectionPtr conn) = 0;
  virtual void onError(ConnectionPtr)
  {
    // default implementation does nothing
  }

protected:
  void send(DataEvent data)
  {
    _sender->send(std::move(data));
  }

private:
  Sender *_sender;
};

} // namespace Netpp
