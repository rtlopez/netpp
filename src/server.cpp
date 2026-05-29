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

  Netpp::SignalHandler signals{&loop, {SIGINT, SIGTERM}};
  Netpp::TcpServer tcpServer{&loop, &dispatcher};

  Netpp::Http::HttpProtocol http{&tcpServer};
  Netpp::Chat::ChatProtocol chat{&tcpServer};
  Netpp::Echo::EchoProtocol echo{&tcpServer};

  tcpServer.listen(HOST, HTTP_PORT, &http);
  tcpServer.listen(HOST, CHAT_PORT, &chat);
  tcpServer.listen(HOST, ECHO_PORT, &echo);

  http.addMiddleware([](Netpp::Http::HttpRequest &req, Netpp::Http::HttpResponse &res) {
    bool result = false;
    if (req.method == "GET" && req.path == "/")
    {
      res.status = 200;
      const char content[] =
          "<html>\n<head><title>Netpp HTTP Server</title></head>\n<body><h1>Welcome to Netpp HTTP Server</h1></body>\n</html>\n";
      res.body = std::vector<uint8_t>{content, content + sizeof(content) - 1};
      result = true;
    }
    if (req.method == "GET" && req.path == "/big")
    {
      res.status = 200;
      std::ostringstream ss;
      ss << "<html>\n<head><title>Big Response</title></head>\n<body><h1>Big Response</h1><p>\n";
      for (int i = 1; i <= 100000; i++)
      {
        ss << "Line aaaa bbbb cccc dddd eeee " << i << "<br>\n";
      }
      ss << "</p></body>\n</html>\n";
      const std::string content = ss.str();
      res.body = std::vector<uint8_t>{content.begin(), content.end()};
      result = true;
    }
    std::cout << "[HTTP] " << req.method << " " << req.path << " " << res.status << "\n";
    return result;
  });

  loop.run();

  return 0;
}
