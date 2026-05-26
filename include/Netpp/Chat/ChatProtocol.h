#pragma once

#include <iostream>
#include <set>
#include <string>
#include <utility>

#include "Netpp/Protocol.h"

namespace Netpp::Chat
{

class ChatProtocol : public Protocol
{
public:
  virtual ~ChatProtocol()
  {
  }

  Status onConnect(ConnectionPtr conn) override
  {
    _clients.insert(conn);

    const char buff[] = "Welcome to the chat room\n";
    ssize_t len = sizeof(buff) - 1;
    ssize_t slen = conn->send(buff, len, 0);
    if (slen != len)
    {
      std::cout << "[CHAT] FIXME: not all data resent\n";
    }

    std::string ip = std::move(conn->getPeerName());
    std::cout << "[CHAT] " << ip << " joined room\n";

    return Protocol::OK;
  }

   Status onDisconnect(ConnectionPtr conn) override
  {
    _clients.erase(conn);

    std::string ip = std::move(conn->getPeerName());
    std::cout << "[CHAT] " << ip << " left room\n";

    return Protocol::OK;
  }

  Status onReceive(ConnectionPtr conn) override
  {
    char buff[1024];
    ssize_t len = conn->recv(buff, sizeof(buff), 0);

    if (len < 0)
    {
      std::cout << "[CHAT] data error: " << len << " " << errno << "\n";
      if (errno == EAGAIN || errno == EWOULDBLOCK)
      {
        return Protocol::OK;
      }
      return Protocol::ERROR;
    }

    if (len == 0)
    {
      std::cout << "[CHAT] empty data\n";
      return Protocol::CLOSE;
    }

    for (const ConnectionPtr &c : _clients)
    {
      if (c == conn)
      {
        continue;
      }
      ssize_t slen = c->send(buff, len, 0);
      if (slen != len)
      {
        std::cout << "[CHAT] FIXME: not all data resent\n";
      }
    }

    buff[len] = '\0';
    if (buff[len - 1] == '\n')
    {
      buff[len - 1] = '\0';
    }
    if (buff[len - 2] == '\r')
    {
      buff[len - 2] = '\0';
    }

    std::cout << "[CHAT] new data: " << buff << "\n";

    return Protocol::OK;
  }

private:
  std::set<ConnectionPtr> _clients;
};

} // namespace Netpp::Chat
