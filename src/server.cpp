#include <csignal>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <sstream>

#include "Netpp/Chat/ChatProtocol.h"
#include "Netpp/DataEvent.h"
#include "Netpp/Echo/EchoProtocol.h"
#include "Netpp/EventLoopEpoll.h"
#include "Netpp/FileStream.h"
#include "Netpp/Http/HttpProtocol.h"
#include "Netpp/Http/HttpRouter.h"
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

  Netpp::Chat::ChatProtocol chat{&tcpServer};
  Netpp::Echo::EchoProtocol echo{&tcpServer};
  Netpp::Http::HttpProtocol http{&tcpServer};
  Netpp::Http::HttpRouter router;

  tcpServer.listen(HOST, HTTP_PORT, &http);
  tcpServer.listen(HOST, CHAT_PORT, &chat);
  tcpServer.listen(HOST, ECHO_PORT, &echo);

  http.addMiddleware(
      [&router](Netpp::Http::HttpRequest &req, Netpp::Http::HttpResponse &res, Netpp::ConnectionPtr conn) {
        router.handle(req, res, conn);
        std::cout << "[HTTP] " << req.method << " " << req.path << " " << res.status << "\n";
      });

  router.on("GET", "/", [](Netpp::Http::HttpRequest &, Netpp::Http::HttpResponse &res, Netpp::ConnectionPtr) {
    const char content[] = "<html>\n<head><title>Netpp HTTP Server</title></head>\n<body>"
                           "<h1>Welcome to Netpp HTTP Server</h1></body>\n</html>\n";
    res.setBody(content, sizeof(content) - 1);
  });

  router.on("GET", "/big", [](Netpp::Http::HttpRequest &, Netpp::Http::HttpResponse &res, Netpp::ConnectionPtr) {
    std::ostringstream ss;
    ss << "<html>\n<head><title>Big Response</title></head>\n<body><h1>Big Response</h1><p>\n";
    for (int i = 1; i <= 100000; i++)
    {
      ss << " 0x" << std::hex << i << " " << std::dec << i << " ";
      if (i % 12 == 0)
      {
        ss << "\n";
      }
    }
    ss << "</p></body>\n</html>\n";
    res.setBody(ss.str());
  });

  router.on("GET", "/stream",
            [](Netpp::Http::HttpRequest &, Netpp::Http::HttpResponse &res, Netpp::ConnectionPtr conn) {
              std::cout << "[HTTP] /stream" << std::endl;
              res.setGenerator([conn, counter = 0]() mutable -> Netpp::DataEvent {
                counter++;
                std::string data = "line " + std::to_string(counter) + "\n";
                return {.conn = conn, .buffer = {data.begin(), data.end()}, .close = counter >= 5};
              });
            });

  router.on("GET", "/file", [](Netpp::Http::HttpRequest &, Netpp::Http::HttpResponse &res, Netpp::ConnectionPtr conn) {
    std::filesystem::path filename = "src/server.cpp";
    std::cout << "[HTTP] " << filename << std::endl;
    if (!std::filesystem::is_regular_file(filename))
    {
      res.status = 404;
      return;
    }
    auto size = std::filesystem::file_size(filename);
    std::cout << "[HTTP] file size: " << size << std::endl;
    res.headers["content-length"] = std::to_string(size);
    res.headers["content-type"] = "text/plain";

    res.setGenerator(Netpp::FileStream{conn, filename.string()});
  });

  loop.run();

  return 0;
}
