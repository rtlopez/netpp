#pragma once

#include <iostream>
#include <string>
#include <utility>

#include "Netpp/Protocol.h"

namespace Netpp::Echo
{

class EchoProtocol : public Protocol
{
public:
  virtual ~EchoProtocol()
  {
  }

  Status onConnect(ConnectionPtr conn) override
  {
    std::string ip = std::move(conn->getPeerName());
    std::cout << "[ECHO] conn accept: " << ip << "\n";
    return Protocol::OK;
  }

  Status onDisconnect(ConnectionPtr conn) override
  {
    std::string ip = std::move(conn->getPeerName());
    std::cout << "[ECHO] conn close: " << ip << "\n";
    return Protocol::OK;
  }

  Status onReceive(ConnectionPtr conn) override
  {
    char buff[1024];
    ssize_t len = conn->recv(buff, sizeof(buff), 0);

    if (len < 0)
    {
      std::cout << "[ECHO] data error: " << len << " " << errno << "\n";
      if (errno == EAGAIN || errno == EWOULDBLOCK)
      {
        return Protocol::OK;
      }
      return Protocol::ERROR;
    }

    if (len == 0)
    {
      std::cout << "[ECHO] empty data\n";
      return Protocol::CLOSE;
    }

    ssize_t slen = conn->send(buff, len, 0);

    if (slen != len)
    {
      std::cout << "[ECHO] FIXME: not all data resent\n";
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

    std::cout << "[ECHO] new data: " << buff << "\n";

    return Protocol::OK;
  }
};

} // namespace Netpp::Echo
