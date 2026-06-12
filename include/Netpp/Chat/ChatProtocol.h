#pragma once

#include <string>

#include "Netpp/Core/TcpHandler.h"
#include "Netpp/Logger/Logger.h"
#include "Netpp/Protocol.h"

namespace Netpp::Chat
{
using Logger::logger;
using Logger::LogLevel;

class ChatProtocol : public Protocol
{
public:
  static constexpr const char *CHAT = "chat";

  ChatProtocol(Core::TcpHandler *server) : _server(server)
  {
    on(CONNECT, [this](ConnectionPtr conn, const DataEvent &) { handleConnect(conn); });

    on(DATA, [this](ConnectionPtr conn, const DataEvent &data) { handleData(conn, data); });
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

private:
  void handleConnect(ConnectionPtr conn)
  {
    std::string welcome = "Welcome to the chat room\n";
    DataEvent resp{DataEvent::Buffer(welcome.begin(), welcome.end())};
    _server->send(conn, std::move(resp));
  }

  void handleData(ConnectionPtr conn, const DataEvent &data)
  {
    auto str = std::string(data.buffer.begin(), data.buffer.end());
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

    logger(CHAT, LogLevel::DEBUG, str);
  }

  Core::TcpHandler *_server;
};

} // namespace Netpp::Chat
