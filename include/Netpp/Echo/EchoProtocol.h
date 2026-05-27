#pragma once

#include <iostream>
#include <string>

#include "Netpp/Protocol.h"

namespace Netpp::Echo
{

class EchoProtocol : public Protocol
{
public:
  virtual ~EchoProtocol()
  {
  }

  void onConnect(ConnectionPtr conn) override
  {
    std::cout << "[ECHO] conn accept: " << conn->getPeerName() << "\n";
  }

  void onDisconnect(ConnectionPtr conn) override
  {
    std::cout << "[ECHO] conn close: " << conn->getPeerName() << "\n";
  }

  void onReceive(DataEvent data) override
  {
    auto str = std::string(data.buffer.begin(), data.buffer.end());

    DataEvent resp{data.conn, DataEvent::Buffer(str.begin(), str.end())};
    send(std::move(resp));

    for (size_t i = 0; i < 2 && !str.empty(); i++)
    {
      auto c = str[str.size() - 1];
      if (c == '\n' || c == '\r')
      {
        str.resize(str.size() - 1);
      }
    }

    std::cout << "[ECHO] new data: " << str << "\n";
  }
};

} // namespace Netpp::Echo
