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
  }

  void onReceive(Netpp::ConnectionPtr conn, Netpp::DataEvent data) override
  {
    if (data.connect)
    {
      _conn = conn;
      return;
    }

    if (data.disconnect)
    {
      _conn.reset();
      _loop->stop();
      return;
    }

    if (!data.buffer.empty())
    {
      std::cout.write(reinterpret_cast<const char *>(data.buffer.data()), data.buffer.size());
      std::cout.flush();
    }
  }

  void send(const std::string &line)
  {
    if (auto conn = _conn.lock())
    {
      Netpp::DataEvent ev{.buffer = Netpp::DataEvent::Buffer(line.begin(), line.end())};
      _handler->send(conn, std::move(ev));
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
  StdinHandler(Netpp::EventLoop *loop, ClientProtocol *protocol) : _loop(loop), _protocol(protocol)
  {
    loop->add(STDIN_FILENO, this);
  }

  void handleReading(Netpp::sock_t s) override
  {
    Netpp::Logger::logger("stdin", Netpp::Logger::LogLevel::DEBUG, s, "read");
    std::string line;
    if (!std::getline(std::cin, line))
    {
      Netpp::Logger::logger("stdin", Netpp::Logger::LogLevel::DEBUG, s, "stopping");
      _loop->stop();
      return;
    }
    line += '\n';
    _protocol->send(line);
  }

  void handleWriting(Netpp::sock_t) override
  {
  }

  void handleError(Netpp::sock_t s) override
  {
    Netpp::Logger::logger("stdin", Netpp::Logger::LogLevel::DEBUG, s, "error");
    _loop->stop();
  }

private:
  Netpp::EventLoop *_loop;
  ClientProtocol *_protocol;
};

int main()
{
  auto logHandler = std::make_unique<Netpp::Logger::LogHandlerSimple>(
      std::make_unique<Netpp::Logger::LogFormatterSimple>(), std::make_unique<Netpp::Logger::LogWriterConsole>());

  Netpp::Logger::Logger::getInstance()->addHandler(std::move(logHandler));
  Netpp::Logger::Logger::getInstance()->setLevel(Netpp::Logger::LogLevel::TRACE);

  Netpp::EventLoopEpoll loop;
  Netpp::SignalHandler signals{&loop, {SIGINT, SIGTERM}};
  Netpp::Core::SingleThreadDispatcher dispatcher{&loop};
  Netpp::Core::TcpHandler tcpHandler{&loop, &dispatcher};

  ClientProtocol protocol{&tcpHandler, &loop};
  StdinHandler stdinHandler{&loop, &protocol};

  tcpHandler.connect(ECHO_HOST, ECHO_PORT, &protocol);

  loop.run();
  dispatcher.stop();

  return 0;
}
