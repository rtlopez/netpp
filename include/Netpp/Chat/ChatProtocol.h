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

    std::string welcome = "Welcome to the chat room\n";
    DataEvent resp{conn, DataEvent::Buffer(welcome.begin(), welcome.end())};
    send(std::move(resp));

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
        DataEvent resp{c, DataEvent::Buffer(str.begin(), str.end())};
        send(std::move(resp));
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
