#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

#include <execinfo.h>
#include <unistd.h>

#include <lyra/lyra.hpp>

#include "Netpp/Chat/ChatProtocol.h"
#include "Netpp/Core/SingleThreadDispatcher.h"
#include "Netpp/Core/TcpHandler.h"
#include "Netpp/Core/ThreadPoolDispatcher.h"
#include "Netpp/DataEvent.h"
#include "Netpp/Echo/EchoProtocol.h"
#include "Netpp/EventLoopEpoll.h"
#include "Netpp/FileStream.h"
#include "Netpp/Http/HttpProtocol.h"
#include "Netpp/Http/HttpRouter.h"
#include "Netpp/Logger/Logger.h"
#include "Netpp/SignalHandler.h"

using Netpp::Logger::logger;
using Netpp::Logger::LogLevel;
static const char *SERVER = "server";

void sigpipe_handler(int signum)
{
  logger(SERVER, LogLevel::INFO, "SIGPIPE caught", signum);
}

[[noreturn]] void terminate_handler()
{
  std::fprintf(stderr, "\n=== std::terminate called ===\n");

  if (auto ex = std::current_exception())
  {
    try
    {
      std::rethrow_exception(ex);
    }
    catch (const std::exception &e)
    {
      std::fprintf(stderr, "uncaught exception: %s\n", e.what());
    }
    catch (...)
    {
      std::fprintf(stderr, "uncaught exception of unknown type\n");
    }
  }

  void *frames[64];
  int n = ::backtrace(frames, 64);
  std::fprintf(stderr, "backtrace (%d frames):\n", n);
  ::backtrace_symbols_fd(frames, n, STDERR_FILENO);
  std::fflush(stderr);

  std::abort();
}

struct CliArgs
{
  CliArgs(int argc, const char **argv)
  {
    // https://www.bfgroup.xyz/Lyra/lyra.html
    // clang-format off
    auto cli = lyra::help(showHelp)
        | lyra::opt(host, "host")["--host"]("Host address to bind")
        | lyra::opt(httpPort, "port")["--http-port"]("HTTP port")
        | lyra::opt(chatPort, "port")["--chat-port"]("Chat port")
        | lyra::opt(echoPort, "port")["--echo-port"]("Echo port")
        | lyra::opt(workerThreads, "count")["--threads"]("Thread pool worker count")
        | lyra::opt(logLevelName, "level")["--log-level"]("Log level: trace, debug, info, warn, error")
          .choices("trace", "debug", "info", "warn", "error");
    // clang-format on

    parseResult = cli.parse({argc, argv});
    if (!parseResult)
    {
      std::cerr << "CLI error: " << parseResult.message() << '\n';
      std::cerr << cli << '\n';
      exit(1);
    }

    if (showHelp)
    {
      std::cout << cli << '\n';
      exit(0);
    }

    auto isValidPort = [](int port) { return port > 0 && port <= 65535; };

    if (!isValidPort(httpPort) || !isValidPort(chatPort) || !isValidPort(echoPort))
    {
      std::cerr << "Invalid port. Allowed range: 1-65535\n";
      exit(1);
    }

    if (workerThreads < 0)
    {
      std::cerr << "Invalid --threads value. It must be greater or equal to 0\n";
      exit(1);
    }

    auto levelOpt = Netpp::Logger::logLevelFromName(logLevelName);
    if (!levelOpt.has_value())
    {
      std::cerr << "Invalid --log-level value: " << logLevelName << '\n';
      exit(1);
    }
    logLevel = levelOpt.value();
  }

  bool showHelp = false;
  std::string host = "127.0.0.1";
  int httpPort = 1234;
  int chatPort = 1235;
  int echoPort = 1236;
  int workerThreads = 16;
  std::string logLevelName = "info";
  LogLevel logLevel = LogLevel::INFO;

private:
  lyra::parse_result parseResult{lyra::result::error("Not parsed yet")};
};

int main(int argc, const char **argv)
{
  std::set_terminate(terminate_handler);

  CliArgs args{argc, argv};

  auto logHandler = std::make_unique<Netpp::Logger::LogHandlerSimple>(
      std::make_unique<Netpp::Logger::LogFormatterSimple>(), std::make_unique<Netpp::Logger::LogWriterConsole>());

  Netpp::Logger::Logger::getInstance()->addHandler(std::move(logHandler));
  Netpp::Logger::Logger::getInstance()->setLevel(args.logLevel);

  logger(SERVER, LogLevel::INFO, "Starting server", "log-level:", Netpp::Logger::logLevelToName(args.logLevel));

  std::signal(SIGPIPE, sigpipe_handler);

  Netpp::EventLoopEpoll loop;

  Netpp::SignalHandler signals{&loop, {SIGINT, SIGTERM}};

  std::unique_ptr<Netpp::Dispatcher> dispatcher;
  if (args.workerThreads > 0)
  {
    dispatcher.reset(new Netpp::Core::ThreadPoolDispatcher(&loop, args.workerThreads));
  }
  else
  {
    dispatcher.reset(new Netpp::Core::SingleThreadDispatcher(&loop));
  }
  Netpp::Core::TcpHandler tcpServer{&loop, dispatcher.get()};

  Netpp::Chat::ChatProtocol chat{&tcpServer};
  Netpp::Echo::EchoProtocol echo{&tcpServer};
  Netpp::Http::HttpProtocol http{&tcpServer};
  Netpp::Http::HttpRouter router;

  tcpServer.listen(args.host.c_str(), static_cast<uint16_t>(args.httpPort), &http);
  tcpServer.listen(args.host.c_str(), static_cast<uint16_t>(args.chatPort), &chat);
  tcpServer.listen(args.host.c_str(), static_cast<uint16_t>(args.echoPort), &echo);

  http.addMiddleware(
      [&router](Netpp::Http::HttpRequest &req, Netpp::Http::HttpResponse &res, Netpp::ConnectionPtr conn) {
        router.handle(req, res, conn);
        logger(SERVER, LogLevel::INFO, "HTTP", conn->getPeerName(), req.method, req.path, res.status);
      });

  router.on("GET", "/", [](Netpp::Http::HttpRequest &, Netpp::Http::HttpResponse &res, Netpp::ConnectionPtr) {
    const char content[] = "<html>\n<head><title>Netpp HTTP Server</title></head>\n<body>"
                           "<h1>Welcome to Netpp HTTP Server</h1></body>\n</html>\n";
    res.setBody(content, sizeof(content) - 1);
  });

  router.on("GET", "/big", [](Netpp::Http::HttpRequest &, Netpp::Http::HttpResponse &res, Netpp::ConnectionPtr) {
    std::ostringstream ss;
    ss << "<html>\n<head><title>Big Response</title></head>\n<body><h1>Big Response</h1><p>\n";
    for (int i = 1; i <= 50000; i++)
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

  router.on("GET", "/stream", [](Netpp::Http::HttpRequest &, Netpp::Http::HttpResponse &res, Netpp::ConnectionPtr) {
    logger(SERVER, LogLevel::INFO, "[HTTP]", "/stream");
    res.setGenerator([counter = 0]() mutable -> Netpp::DataEvent {
      counter++;
      std::string data = "line " + std::to_string(counter) + "\n";
      auto eventType = counter >= 5 ? Netpp::EventType::DISCONNECT : Netpp::EventType::DATA;
      return {.buffer = {data.begin(), data.end()}, .eventType = eventType};
    });
  });

  router.on("GET", "/file", [](Netpp::Http::HttpRequest &, Netpp::Http::HttpResponse &res, Netpp::ConnectionPtr) {
    std::filesystem::path filename = "src/server.cpp";
    // std::cout << "[HTTP] " << filename << std::endl;
    if (!std::filesystem::is_regular_file(filename))
    {
      res.status = 404;
      return;
    }

    std::ifstream file(filename, std::ios::binary | std::ios::in);
    if (!file)
    {
      res.status = 500;
      return;
    }
    auto size = std::filesystem::file_size(filename);
    // std::cout << "[HTTP] file size: " << size << std::endl;

    res.headers["content-length"] = std::to_string(size);
    res.headers["content-type"] = "text/plain";

    res.setGenerator(Netpp::FileStream{filename.string(), std::move(file)});
  });

  loop.run();

  dispatcher->stop();

  logger(SERVER, LogLevel::INFO, "Server stopping");

  return 0;
}
