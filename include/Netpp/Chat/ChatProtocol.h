#pragma once

#include <iostream>
#include <string>
#include <unordered_set>

#include "Netpp/Protocol.h"

namespace Netpp::Chat
{

class ChatProtocol : public Protocol
{
public:
  virtual ~ChatProtocol()
  {
  }

  void onConnect(ConnectionPtr conn) override
  {
    _clients.insert(conn);

    const char buff[] = "Welcome to the chat room\n";
    ssize_t len = sizeof(buff) - 1;
    ssize_t slen = conn->send(buff, len, 0);
    if (slen != len)
    {
      std::cout << "[CHAT] FIXME: not all data resent\n";
    }

    std::cout << "[CHAT] " << conn->getPeerName() << " joined room\n";
  }

  void onDisconnect(ConnectionPtr conn) override
  {
    _clients.erase(conn);

    std::cout << "[CHAT] " << conn->getPeerName() << " left room\n";
  }

  void onReceive(DataEvent data) override
  {
    auto str = std::string(data.data.begin(), data.data.end());

    for (const ConnectionPtr &c : _clients)
    {
      if (c != data.conn)
      {
        auto slen = c->send(str.c_str(), str.size(), 0);
        if (slen != (ssize_t)str.size())
        {
          std::cout << "[CHAT] FIXME: not all data resent\n";
        }
      }
    }

    for (size_t i = 0; i < 2 && !str.empty(); i++)
    {
      auto c = str[str.size() - 1];
      if (c == '\n' || c == '\r')
      {
        str.resize(str.size() - 1);
      }
    }

    std::cout << "[CHAT] new data: " << str << "\n";
  }

private:
  std::unordered_set<ConnectionPtr> _clients;
};

} // namespace Netpp::Chat
