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
    if (data.connect)
    {
      return;
    }

    auto str = std::string(data.buffer.begin(), data.buffer.end());

    bool close = str.starts_with("close");
    bool infinite = str.starts_with("inf");

    DataEvent resp{.buffer = DataEvent::Buffer(str.begin(), str.end()), .close = close};
    _server->send(conn, std::move(resp));

    if (infinite)
    {
      _server->send(conn, [counter = 0]() mutable -> DataEvent {
        counter++;
        logger(ECHO, LogLevel::DEBUG).log(counter);
        std::string data = "echo " + std::to_string(counter) + "\n";
        return {.buffer = {data.begin(), data.end()}};
      });
    }

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
