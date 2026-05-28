#include <csignal>
#include <cstdint>
#include <cstdio>

#include "Netpp/Chat/ChatProtocol.h"
#include "Netpp/Echo/EchoProtocol.h"
#include "Netpp/EventLoopEpoll.h"
#include "Netpp/Http/HttpProtocol.h"
#include "Netpp/SignalHandler.h"
#include "Netpp/SingleThreadDispatcher.h"
#include "Netpp/TcpServer.h"

static const char *HOST = "127.0.0.1";
static constexpr uint16_t HTTP_PORT = 1234;
static constexpr uint16_t CHAT_PORT = 1235;
static constexpr uint16_t ECHO_PORT = 1236;

void sigpipe_handler(int signum)
{
  std::printf("Caught signal SIGPIPE %d\n", signum);
}

int main()
{
  std::signal(SIGPIPE, sigpipe_handler);

  Netpp::EventLoopEpoll loop;

  Netpp::SingleThreadDispatcher dispatcher;

  Netpp::Http::HttpProtocol http{&dispatcher};
  Netpp::Chat::ChatProtocol chat{&dispatcher};
  Netpp::Echo::EchoProtocol echo{&dispatcher};

  Netpp::SignalHandler signals{&loop, {SIGINT, SIGTERM}};
  Netpp::TcpServer httpServer{HOST, HTTP_PORT, &loop, &http, &dispatcher};
  Netpp::TcpServer chatServer{HOST, CHAT_PORT, &loop, &chat, &dispatcher};
  Netpp::TcpServer echoServer{HOST, ECHO_PORT, &loop, &echo, &dispatcher};

  loop.run();

  return 0;
}
