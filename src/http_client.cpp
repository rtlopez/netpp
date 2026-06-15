#include <future>
#include <iostream>
#include <string>
#include <thread>

#include "Netpp/Core/SingleThreadDispatcher.h"
#include "Netpp/Core/TcpHandler.h"
#include "Netpp/Core/TimerHandler.h"
#include "Netpp/EventLoopEpoll.h"
#include "Netpp/Http/HttpClientProtocol.h"
#include "Netpp/Logger/Logger.h"
#include "Netpp/SignalHandler.h"

int main(int argc, char *argv[])
{
  const char *host = argc > 1 ? argv[1] : "127.0.0.1";
  uint16_t port = argc > 2 ? static_cast<uint16_t>(std::stoi(argv[2])) : 80;
  const char *path = argc > 3 ? argv[3] : "/";

  auto logHandler = std::make_unique<Netpp::Logger::LogHandlerSimple>(
      std::make_unique<Netpp::Logger::LogFormatterSimple>(), std::make_unique<Netpp::Logger::LogWriterConsole>());
  Netpp::Logger::Logger::getInstance()->addHandler(std::move(logHandler));
  Netpp::Logger::Logger::getInstance()->setLevel(Netpp::Logger::LogLevel::DEBUG);

  Netpp::EventLoopEpoll loop;
  Netpp::LoopControlHandler loopControl{&loop};
  Netpp::SignalHandler signals{&loop, &loopControl, {SIGINT, SIGTERM}};
  Netpp::Core::TimerHandler timers{&loop};
  Netpp::Core::SingleThreadDispatcher dispatcher{&loop};
  Netpp::Core::TcpHandler tcpHandler{&loop, &dispatcher, &timers};

  Netpp::Http::HttpClientProtocol http{&tcpHandler};

  // Issue GET request - returns std::future<HttpResponse>
  auto future = http.get(host, port, path);

  // Run event loop in a separate thread to enable pseudo-blocking via future.get()
  std::thread loopThread([&loop]() { loop.run(); });

  // Block until the response arrives (or timeout)
  auto status = future.wait_for(std::chrono::seconds(10));
  if (status == std::future_status::ready)
  {
    try
    {
      auto response = future.get();
      std::cout << response.str() << "\n";
      std::cout.write(reinterpret_cast<const char *>(response.body.data()), response.body.size());
      std::cout << "\n";
    }
    catch (const std::exception &e)
    {
      std::cerr << "request failed: " << e.what() << "\n";
    }
  }
  else
  {
    std::cerr << "request timed out\n";
  }

  loopControl.stop();
  loopThread.join();
  dispatcher.stop();

  return 0;
}
