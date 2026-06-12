#include <iostream>
#include <string>
#include <unistd.h>

#include "Netpp/Core/SingleThreadDispatcher.h"
#include "Netpp/Core/TcpHandler.h"
#include "Netpp/DataEvent.h"
#include "Netpp/EventLoopEpoll.h"
#include "Netpp/EventLoopHandler.h"
#include "Netpp/Logger/Logger.h"
#include "Netpp/Protocol.h"
#include "Netpp/SignalHandler.h"

static constexpr const char *ECHO_HOST = "127.0.0.1";
static constexpr uint16_t ECHO_PORT = 1236;

class ClientProtocol : public Netpp::Protocol
{
public:
  ClientProtocol(Netpp::Core::TcpHandler *handler, Netpp::EventLoop *loop) : _handler(handler), _loop(loop)
  {
    on(Netpp::EventType::CONNECT, [this](Netpp::ConnectionPtr conn, const Netpp::DataEvent &) {
      // store connection for sending data from stdin handler
      _conn = conn;
    });

    on(Netpp::EventType::DISCONNECT, [this](Netpp::ConnectionPtr, const Netpp::DataEvent &) {
      // stop loop on disconnection
      _conn.reset();
      _loop->stop();
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
  Netpp::Core::TcpHandler *_handler;
  Netpp::EventLoop *_loop;
  Netpp::ConnectionWeakPtr _conn;
};

class StdinHandler : public Netpp::EventLoopHandler
{
public:
  StdinHandler(Netpp::EventLoop *loop, std::function<void(const std::string &)> receiver)
      : _loop(loop), _receiver(receiver)
  {
    // add stdin fd to event loop
    _loop->add(STDIN_FILENO, this);
  }

  void handleReading(Netpp::sock_t s) override
  {
    // read a line from stdin and send to receiver callback
    std::string line;
    if (!std::getline(std::cin, line))
    {
      Netpp::Logger::logger("stdin", Netpp::Logger::LogLevel::DEBUG, s, "stopping");
      _loop->stop();
      return;
    }
    line += '\n';
    _receiver(line);
  }

  void handleWriting(Netpp::sock_t) override
  {
    // not used for stdin
  }

  void handleError(Netpp::sock_t s) override
  {
    // log error and stop loop
    Netpp::Logger::logger("stdin", Netpp::Logger::LogLevel::DEBUG, s, "error");
    _loop->stop();
  }

private:
  Netpp::EventLoop *_loop;
  std::function<void(const std::string &)> _receiver;
};

int main()
{
  auto logHandler = std::make_unique<Netpp::Logger::LogHandlerSimple>(
      std::make_unique<Netpp::Logger::LogFormatterSimple>(), std::make_unique<Netpp::Logger::LogWriterConsole>());

  Netpp::Logger::Logger::getInstance()->addHandler(std::move(logHandler));
  Netpp::Logger::Logger::getInstance()->setLevel(Netpp::Logger::LogLevel::DEBUG);

  Netpp::EventLoopEpoll loop;
  Netpp::SignalHandler signals{&loop, {SIGINT, SIGTERM}};
  Netpp::Core::SingleThreadDispatcher dispatcher{&loop};
  Netpp::Core::TcpHandler tcpHandler{&loop, &dispatcher};

  ClientProtocol protocol{&tcpHandler, &loop};
  StdinHandler stdinHandler{&loop, [&protocol](const std::string &line) { protocol.send(line); }};

  tcpHandler.connect(ECHO_HOST, ECHO_PORT, &protocol);

  loop.run();
  dispatcher.stop();

  return 0;
}
