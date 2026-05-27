#pragma once

#include <iostream>
#include <queue>

#include "Dispatcher.h"
#include "NetppDebug.h"
#include "Protocol.h"

namespace Netpp
{

class SingleThreadDispatcher : public Dispatcher
{
public:
  void send(DataEvent data) override
  {
    _sendQueue.push(std::move(data));
  }

  void post(DataEvent data, Protocol *target) override
  {
    _recvQueue.push({std::move(data), target});
  }

  void drain(std::function<void(sock_t)> handleClose) override
  {
    while (!_recvQueue.empty())
    {
      auto &item = _recvQueue.front();
      try
      {
        item.target->onReceive(std::move(item.data));
      }
      catch (...)
      {
        debug("SingleThreadDispatcher::drain", "exception in onReceive");
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
          std::cout << "[DISPATCHER] FIXME: not all data sent\n";
        }
        debug("SingleThreadDispatcher::drain", slen, data.close);
        if (data.close)
        {
          handleClose(data.conn->getId());
        }
      }
      catch (...)
      {
        debug("SingleThreadDispatcher::drain", "exception in onSend");
      }
      _sendQueue.pop();
    }
  }

private:
  struct RecvItem
  {
    DataEvent data;
    Protocol *target;
  };

  std::queue<RecvItem> _recvQueue;
  std::queue<DataEvent> _sendQueue;
};

} // namespace Netpp
