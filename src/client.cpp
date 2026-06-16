#include <iostream>
#include <string>
#include <unistd.h>

#include "Netpp/Core/SingleThreadDispatcher.h"
#include "Netpp/Core/StdinHandler.h"
#include "Netpp/Core/TcpHandler.h"
#include "Netpp/Core/TimerHandler.h"
#include "Netpp/DataEvent.h"
#include "Netpp/EventLoopEpoll.h"
#include "Netpp/Logger/Logger.h"
#include "Netpp/LoopControlHandler.h"
#include "Netpp/Protocol.h"
#include "Netpp/SignalHandler.h"
#include "Netpp/TransportHandler.h"

static constexpr const char *ECHO_HOST = "127.0.0.1";
static constexpr uint16_t ECHO_PORT = 1236;

class ClientProtocol : public Netpp::Protocol
{
public:
  ClientProtocol(Netpp::TransportHandler *handler, Netpp::LoopControlHandler *loopControl)
      : _handler(handler), _loopControl(loopControl)
  {
    on(Netpp::EventType::CONNECT, [this](Netpp::ConnectionPtr conn, const Netpp::DataEvent &) {
      // store connection for sending data from stdin handler
      _conn = conn;
    });

    on(Netpp::EventType::DISCONNECT, [this](Netpp::ConnectionPtr, const Netpp::DataEvent &) {
      // stop loop on disconnection
      _conn.reset();
      _loopControl->stop();
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
  Netpp::LoopControlHandler *_loopControl;
  Netpp::ConnectionWeakPtr _conn;
};

int main()
{
  auto logHandler = std::make_unique<Netpp::Logger::LogHandlerSimple>(
      std::make_unique<Netpp::Logger::LogFormatterSimple>(), std::make_unique<Netpp::Logger::LogWriterConsole>());

  Netpp::Logger::Logger::getInstance()->addHandler(std::move(logHandler));
  Netpp::Logger::Logger::getInstance()->setLevel(Netpp::Logger::LogLevel::DEBUG);

  Netpp::EventLoopEpoll loop;
  Netpp::LoopControlHandler loopControl{&loop};
  Netpp::SignalHandler signals{&loop, &loopControl, {SIGINT, SIGTERM}};
  Netpp::Core::TimerHandler timer{&loop};
  Netpp::Core::SingleThreadDispatcher dispatcher{&loop};
  Netpp::Core::TcpHandler tcpHandler{&loop, &dispatcher, &timer};

  ClientProtocol protocol{&tcpHandler, &loopControl};
  Netpp::Core::StdinHandler stdinHandler{&loop, &loopControl,
                                         [&protocol](const std::string &line) { protocol.send(line); }};

  tcpHandler.connect(ECHO_HOST, ECHO_PORT, &protocol);

  loop.run();
  dispatcher.stop();

  return 0;
}
