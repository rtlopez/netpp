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

#include <unistd.h>

#include <lyra/lyra.hpp>

#include "Netpp/Chat/ChatProtocol.h"
#include "Netpp/Core/TcpHandler.h"
#include "Netpp/Core/UdpHandler.h"
#include "Netpp/DataEvent.h"
#include "Netpp/Echo/EchoProtocol.h"
#include "Netpp/FileStream.h"
#include "Netpp/Http/HttpProtocol.h"
#include "Netpp/Http/HttpRouter.h"
#include "Netpp/Stack.h"

using Netpp::Logger::logger;
using Netpp::Logger::LogLevel;
static const char *SERVER = "server";

void sigpipe_handler(int signum)
{
  logger(SERVER, LogLevel::INFO, "SIGPIPE caught", signum);
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

    auto result = cli.parse({argc, argv});
    if (!result)
    {
      std::cerr << "CLI error: " << result.message() << '\n';
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
};

int main(int argc, const char **argv)
{
  std::set_terminate(netpp_terminate_handler);

  CliArgs args{argc, argv};

  Netpp::StackConfig config;
  if (args.workerThreads > 0)
  {
    config.dispatcherType = Netpp::StackConfig::DispatcherType::ThreadPool;
    config.threadPoolSize = static_cast<size_t>(args.workerThreads);
  }
  config.logLevel = args.logLevel;

  Netpp::Stack stack(config);

  logger(SERVER, LogLevel::INFO, "Starting server", "log-level:", Netpp::Logger::logLevelToName(args.logLevel));

  std::signal(SIGPIPE, sigpipe_handler);

  auto &tcp = stack.tcp();
  auto &udp = stack.udp();

  Netpp::Chat::ChatProtocol chat{&tcp};
  Netpp::Echo::EchoProtocol echoUdp{&udp};
  Netpp::Echo::EchoProtocol echoTcp{&tcp};
  Netpp::Http::HttpProtocol http{&tcp};

  Netpp::Http::HttpRouter router;

  tcp.listen(args.host.c_str(), static_cast<uint16_t>(args.httpPort), &http);
  tcp.listen(args.host.c_str(), static_cast<uint16_t>(args.chatPort), &chat);
  tcp.listen(args.host.c_str(), static_cast<uint16_t>(args.echoPort), &echoTcp);
  udp.listen(args.host.c_str(), 9000, &echoUdp);

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
      ss << " 0x" << std::hex << i << " " << std::dec << std::setw(5) << std::setfill('0') << i << " ";
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
      auto eventType = counter >= 5 ? Netpp::EventType::DONE : Netpp::EventType::DATA;
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

    auto stream = std::make_unique<Netpp::FileStream>(filename.string(), std::move(file));
    res.setGenerator([stream = std::move(stream)]() { return (*stream)(); });
  });

  router.on("GET", "/src", [](Netpp::Http::HttpRequest &, Netpp::Http::HttpResponse &res, Netpp::ConnectionPtr) {
    std::filesystem::path srcDir = "src";

    if (!std::filesystem::is_directory(srcDir))
    {
      res.status = 404;
      return;
    }

    std::ostringstream ss;
    ss << "<html>\n<head>\n<title>src/ Directory</title>\n<style>"
       << "body { font-family: monospace; margin: 20px; }"
       << "table { border-collapse: collapse; width: 100%; }"
       << "th, td { border: 1px solid #ccc; padding: 8px; text-align: left; }"
       << "th.right, td.right { border: 1px solid #ccc; padding: 8px; text-align: right; }"
       << "th { background-color: #f0f0f0; }"
       << "</style>\n</head>\n<body>\n"
       << "<h1>Directory: src/</h1>\n"
       << "<table>\n<thead>\n<tr><th>File</th><th class=\"right\">Size</th><th "
          "class=\"right\">Modified</th></tr>\n</thead>\n<tbody>\n";

    try
    {
      for (const auto &entry : std::filesystem::directory_iterator(srcDir))
      {
        if (entry.is_regular_file())
        {
          auto size = entry.file_size();
          auto lastWrite = entry.last_write_time();

          // time to string
          auto sctp = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
              lastWrite - std::filesystem::file_time_type::clock::now() + std::chrono::system_clock::now());
          auto tt = std::chrono::system_clock::to_time_t(sctp);

          std::string timeStr(std::ctime(&tt));
          timeStr.pop_back(); // Remove newline

          ss << "<tr><td><a href=\"/src/" << entry.path().filename().string() << "\">"
             << entry.path().filename().string() << "</a></td>"
             << "<td class=\"right\">" << size << " B</td>"
             << "<td class=\"right\">" << timeStr << "</td></tr>\n";
        }
      }
    }
    catch (const std::exception &e)
    {
      logger(SERVER, LogLevel::ERROR, "Error reading src directory:", e.what());
      res.status = 500;
      return;
    }

    ss << "</tbody>\n</table>\n</body>\n</html>\n";
    res.setBody(ss.str());
  });

  stack.run();

  logger(SERVER, LogLevel::INFO, "Server stopping");

  return 0;
}
