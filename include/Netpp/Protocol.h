#pragma once

#include <functional>
#include <queue>

#include "Connection.h"
#include "DataEvent.h"

namespace Netpp
{

class Protocol
{
public:
  virtual ~Protocol()
  {
  }

  virtual void onConnect(ConnectionPtr conn) = 0;
  virtual void onReceive(DataEvent data) = 0;
  virtual void onDisconnect(ConnectionPtr conn) = 0;
  virtual void onError(ConnectionPtr)
  {
    // default implementation does nothing
  }

  virtual void receive(DataEvent data)
  {
    _recvQueue.push(std::move(data));
  }

  virtual void send(DataEvent data)
  {
    _sendQueue.push(std::move(data));
  }

  virtual void flush(std::function<void(sock_t)> handleClose)
  {
    while (!_recvQueue.empty())
    {
      auto &data = _recvQueue.front();
      try
      {
        onReceive(std::move(data));
      }
      catch (...)
      {
        debug("Protocol::flush", "exception in onReceive");
      }
      _recvQueue.pop();
    }

    while (!_sendQueue.empty())
    {
      auto &data = _sendQueue.front();
      try
      {
        const auto slen = data.conn->send(data.buffer.data(), data.buffer.size(), 0);
        if (slen != (int)data.buffer.size())
        {
          std::cout << "[PROTOCOL] FIXME: not all data sent\n";
        }
        debug("Protocol::flush", slen, data.close);
        if (data.close)
        {
          handleClose(data.conn->getId());
        }
      }
      catch (...)
      {
        debug("Protocol::flush", "exception in onSend");
      }
      _sendQueue.pop();
    }
  }

private:
  std::queue<DataEvent> _recvQueue;
  std::queue<DataEvent> _sendQueue;
};

} // namespace Netpp
