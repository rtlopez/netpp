#pragma once

#include <string>

#include "Netpp/Logger/Logger.h"
#include "Netpp/Protocol.h"
#include "Netpp/TcpServer.h"

namespace Netpp::Echo
{

using Netpp::Logger::logger;
using Netpp::Logger::LogLevel;
static const char *ECHO = "echo";

class EchoProtocol : public Protocol
{
public:
  EchoProtocol(TcpServer *server) : _server(server)
  {
  }

  virtual ~EchoProtocol()
  {
  }

  void onReceive(ConnectionPtr conn, DataEvent data) override
  {
    auto str = std::string(data.buffer.begin(), data.buffer.end());

    DataEvent resp{DataEvent::Buffer(str.begin(), str.end())};
    _server->send(conn, std::move(resp));

    for (size_t i = 0; i < 2 && !str.empty(); i++)
    {
      auto c = str[str.size() - 1];
      if (c == '\n' || c == '\r')
      {
        str.resize(str.size() - 1);
      }
    }

    logger(ECHO, LogLevel::DEBUG).log(str);
  }

private:
  TcpServer *_server;
};

} // namespace Netpp::Echo
