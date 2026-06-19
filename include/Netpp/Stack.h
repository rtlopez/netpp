#pragma once

#include <chrono>
#include <memory>
#include <string>
#include <thread>

#include "Netpp/Logger/Logger.h"

namespace Netpp
{

class EventLoop;
class Dispatcher;
class TimerScheduler;

namespace Core
{
class TcpHandler;
class UdpHandler;
} // namespace Core

namespace Dns
{
class DnsProtocol;
}

namespace Http
{
class HttpClientProtocol;
}

struct StackConfig
{
  enum class DispatcherType
  {
    SingleThread,
    ThreadPool
  };

  DispatcherType dispatcherType = DispatcherType::SingleThread;
  size_t threadPoolSize = 8;

  Logger::LogLevel logLevel = Logger::LogLevel::INFO;
  bool consoleLog = true;

  std::string dnsNameserver = "8.8.8.8";
  uint16_t dnsPort = 53;
  std::chrono::milliseconds dnsTimeout = std::chrono::seconds(1);
};

class StackBuilder;

class Stack
{
public:
  explicit Stack(StackConfig config = {});
  ~Stack();

  Stack(const Stack &) = delete;
  Stack &operator=(const Stack &) = delete;

  static StackBuilder builder();

  // Infrastructure (lazy-created on first access)
  EventLoop &loop();
  Dispatcher &dispatcher();
  TimerScheduler &timer();

  // Transport (lazy-created, auto-wires dependencies)
  Core::TcpHandler &tcp();
  Core::UdpHandler &udp();

  // Protocols (lazy-created, auto-wires transport)
  Dns::DnsProtocol &dns();
  Http::HttpClientProtocol &httpClient();

  // Lifecycle
  void run();
  std::thread runInBackground();
  void stop();

private:
  void setupLogger();

  StackConfig _config;

  // Destruction order (reverse of declaration):
  //   protocols -> transports -> timer -> dispatcher -> loop
  struct Impl;
  std::unique_ptr<Impl> _impl;
};

class StackBuilder
{
public:
  StackBuilder &singleThread();
  StackBuilder &threadPool(size_t numThreads = 8);
  StackBuilder &logLevel(Logger::LogLevel level);
  StackBuilder &noLog();
  StackBuilder &dnsNameserver(const std::string &ns, uint16_t port = 53);
  StackBuilder &dnsTimeout(std::chrono::milliseconds timeout);
  Stack build();

private:
  StackConfig _config;
};

} // namespace Netpp
