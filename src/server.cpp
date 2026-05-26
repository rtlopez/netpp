#include <csignal>
#include <cstdint>
#include <cstdio>

#include "Netpp/Chat/ChatProtocol.h"
#include "Netpp/Echo/EchoProtocol.h"
#include "Netpp/EventLoopEpoll.h"
#include "Netpp/Http/HttpProtocol.h"
#include "Netpp/SignalHandler.h"
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

  Netpp::Http::HttpProtocol http;
  Netpp::Chat::ChatProtocol chat;
  Netpp::Echo::EchoProtocol echo;

  Netpp::SignalHandler signals{&loop, {SIGINT, SIGTERM}};
  Netpp::TcpServer httpServer{HOST, HTTP_PORT, &loop, &http};
  Netpp::TcpServer chatServer{HOST, CHAT_PORT, &loop, &chat};
  Netpp::TcpServer echoServer{HOST, ECHO_PORT, &loop, &echo};

  loop.run();

  return 0;
}
