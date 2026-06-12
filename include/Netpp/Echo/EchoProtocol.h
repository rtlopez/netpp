#pragma once

#include <string>

#include "Netpp/Core/TcpHandler.h"
#include "Netpp/DataEvent.h"
#include "Netpp/Logger/Logger.h"
#include "Netpp/Protocol.h"

namespace Netpp::Echo
{

using Logger::logger;
using Logger::LogLevel;

class EchoProtocol : public Protocol
{
public:
  static constexpr const char *ECHO = "echo";

  EchoProtocol(Core::TcpHandler *server) : _server(server)
  {
    on(DATA, [this](ConnectionPtr conn, const DataEvent &data) { handleData(conn, data); });
  }

  virtual ~EchoProtocol()
  {
  }

private:
  void handleData(ConnectionPtr conn, const DataEvent &data)
  {
    auto str = std::string(data.buffer.begin(), data.buffer.end());

    auto close = str.starts_with("close") || str.starts_with("exit") || str.starts_with("quit");
    bool infinite = str.starts_with("inf");

    EventType eventType = close ? EventType::DISCONNECT : EventType::DATA;
    DataEvent resp{.buffer = {str.begin(), str.end()}, .eventType = eventType};
    _server->send(conn, std::move(resp));

    if (infinite)
    {
      _server->send(conn, [counter = 0]() mutable -> DataEvent {
        counter++;
        logger(ECHO, LogLevel::DEBUG, counter);
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

    logger(ECHO, LogLevel::DEBUG, str);
  }

  Core::TcpHandler *_server;
};

} // namespace Netpp::Echo
