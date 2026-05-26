#include <csignal>
#include <cstdio>

#include "Netpp/EventLoopEpoll.h"
#include "Netpp/Http/HttpProtocol.h"
#include "Netpp/Chat/ChatProtocol.h"
#include "Netpp/Echo/EchoProtocol.h"
#include "Netpp/SignalHandler.h"
#include "Netpp/TcpServer.h"

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
  Netpp::TcpServer httpServer{"127.0.0.1", 1234, &loop, &http};
  Netpp::TcpServer chatServer{"127.0.0.1", 1235, &loop, &chat};
  Netpp::TcpServer echoServer{"127.0.0.1", 1236, &loop, &echo};

  loop.run();

  return 0;
}
