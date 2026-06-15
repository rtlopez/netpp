#pragma once

#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "Netpp/Connection.h"
#include "Netpp/Logger/Logger.h"
#include "Netpp/Protocol.h"
#include "Netpp/TransportHandler.h"

namespace Netpp::Chat
{
using Logger::logger;
using Logger::LogLevel;

class ChatProtocol : public Protocol
{
public:
  static constexpr const char *CHAT = "chat";

  ChatProtocol(TransportHandler *server) : _server(server)
  {
    on(CONNECT, [this](ConnectionPtr conn, const DataEvent &) { handleConnect(conn); });

    on(DISCONNECT, [this](ConnectionPtr conn, const DataEvent &) { handleDisconnect(conn); });

    on(DATA, [this](ConnectionPtr conn, const DataEvent &data) { handleData(conn, data); });
  }

  virtual ~ChatProtocol()
  {
  }

private:
  void handleConnect(ConnectionPtr conn)
  {
    addClient(conn);

    std::string welcome = "Welcome to the chat room\n";
    _server->send(conn, {.buffer = {welcome.begin(), welcome.end()}});

    std::string joinMsg = "A new user has joined the chat " + conn->getPeerName() + "\n";
    broadcast(conn, joinMsg);
  }

  void handleDisconnect(ConnectionPtr conn)
  {
    removeClient(conn);

    std::string leaveMsg = "A user has left the chat " + conn->getPeerName() + "\n";
    broadcast(conn, leaveMsg);
  }

  void handleData(ConnectionPtr conn, const DataEvent &data)
  {
    auto str = std::string(data.buffer.begin(), data.buffer.end());

    broadcast(conn, str);

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

  void broadcast(ConnectionPtr conn, const std::string &message)
  {
    for (const auto &w : getClients())
    {
      auto c = w.lock();
      if (c && c != conn)
      {
        _server->send(c, {.buffer = {message.begin(), message.end()}});
      }
    }
  }

  std::vector<ConnectionWeakPtr> getClients()
  {
    std::vector<ConnectionWeakPtr> clients;
    {
      std::shared_lock lock(_clientsMutex);
      clients.reserve(_clients.size());
      for (const auto &w : _clients)
      {
        clients.push_back(w.second);
      }
    }
    return clients;
  }

  void addClient(ConnectionPtr conn)
  {
    std::unique_lock lock(_clientsMutex);
    _clients[conn->getId()] = ConnectionWeakPtr{conn};
  }

  void removeClient(ConnectionPtr conn)
  {
    std::unique_lock lock(_clientsMutex);
    _clients.erase(conn->getId());
  }

  TransportHandler *_server;

  // Writes (connect/disconnect) are exclusive, broadcasts can snapshot clients concurrently.
  std::shared_mutex _clientsMutex;
  std::unordered_map<int, ConnectionWeakPtr> _clients;
};

} // namespace Netpp::Chat
