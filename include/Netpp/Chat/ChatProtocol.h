#pragma once

#include <string>

#include "Netpp/Logger/Logger.h"
#include "Netpp/Protocol.h"
#include "Netpp/TcpServer.h"

namespace Netpp::Chat
{

using Netpp::Logger::logger;
using Netpp::Logger::LogLevel;
static const char *CHAT = "chat";

class ChatProtocol : public Protocol
{
public:
  ChatProtocol(TcpServer *server) : _server(server)
  {
  }

  virtual ~ChatProtocol()
  {
  }

  std::shared_ptr<int> getContext(ConnectionPtr conn)
  {
    auto context = conn->getContext<int>();
    if (!context)
    {
      context = std::make_shared<int>(0);
      conn->setContext(context);
    }
    return context;
  }

  void onReceive(ConnectionPtr conn, DataEvent data) override
  {
    auto str = std::string(data.buffer.begin(), data.buffer.end());

    if (data.connect)
    {
      std::string welcome = "Welcome to the chat room\n";
      DataEvent resp{DataEvent::Buffer(welcome.begin(), welcome.end())};
      _server->send(conn, std::move(resp));
      return;
    }

    auto clients = _server->getProtocolConnections(this);
    for (const ConnectionWeakPtr &w : clients)
    {
      auto c = w.lock();
      if (c && c != conn)
      {
        DataEvent resp{DataEvent::Buffer(str.begin(), str.end())};
        _server->send(c, std::move(resp));
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

    logger(CHAT, LogLevel::DEBUG).log(str);
  }

private:
  TcpServer *_server;
};

} // namespace Netpp::Chat
