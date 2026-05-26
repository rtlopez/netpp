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
    auto str = std::string(data.data.begin(), data.data.end());

    auto slen = data.conn->send(str.c_str(), str.size(), 0);

    if (slen != (ssize_t)str.size())
    {
      std::cout << "[ECHO] FIXME: not all data resent\n";
    }

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
