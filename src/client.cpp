#include <iostream>
#include <string>

#include "Netpp/Core/StdinHandler.h"
#include "Netpp/Core/TcpHandler.h"
#include "Netpp/DataEvent.h"
#include "Netpp/MoveOnlyFunction.h"
#include "Netpp/Protocol.h"
#include "Netpp/Stack.h"
#include "Netpp/TransportHandler.h"

static constexpr const char *ECHO_HOST = "127.0.0.1";
static constexpr uint16_t ECHO_PORT = 1236;

class ClientProtocol : public Netpp::Protocol
{
public:
  ClientProtocol(Netpp::TransportHandler *handler, Netpp::MoveOnlyFunction<void()> onDisconnect)
      : _handler(handler), _onDisconnect(std::move(onDisconnect))
  {
    on(Netpp::EventType::CONNECT, [this](Netpp::ConnectionPtr conn, const Netpp::DataEvent &) {
      // store connection for sending data from stdin handler
      _conn = conn;
    });

    on(Netpp::EventType::DISCONNECT, [this](Netpp::ConnectionPtr, const Netpp::DataEvent &) {
      // stop loop on disconnection
      _conn.reset();
      _onDisconnect();
    });

    on(Netpp::EventType::DATA, [](Netpp::ConnectionPtr, const Netpp::DataEvent &data) {
      // print received data to stdout
      if (!data.buffer.empty())
      {
        std::cout.write(reinterpret_cast<const char *>(data.buffer.data()), data.buffer.size());
        std::cout.flush();
      }
    });
  }

  void send(const std::string &line)
  {
    // send data to connected server
    if (auto conn = _conn.lock())
    {
      Netpp::DataEvent data{.buffer = {line.begin(), line.end()}, .eventType = Netpp::EventType::DATA};
      _handler->send(conn, std::move(data));
    }
  }

private:
  Netpp::TransportHandler *_handler;
  Netpp::ConnectionWeakPtr _conn;
  Netpp::MoveOnlyFunction<void()> _onDisconnect;
};

int main()
{
  Netpp::Stack stack({.logLevel = Netpp::Logger::LogLevel::DEBUG});

  ClientProtocol protocol{&stack.tcp(), [&stack]() { stack.stop(); }};
  Netpp::Core::StdinHandler stdinHandler{&stack.loop(), [&protocol](const std::string &line) { protocol.send(line); }};

  stack.tcp().connect(ECHO_HOST, ECHO_PORT, &protocol);

  stack.run();

  return 0;
}
