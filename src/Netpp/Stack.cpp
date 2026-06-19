#include "Netpp/Stack.h"

#include "Netpp/Core/SingleThreadDispatcher.h"
#include "Netpp/Core/TcpHandler.h"
#include "Netpp/Core/ThreadPoolDispatcher.h"
#include "Netpp/Core/TimerHandler.h"
#include "Netpp/Core/UdpHandler.h"
#include "Netpp/Dns/DnsProtocol.h"
#include "Netpp/EventLoop.h"
#include "Netpp/Http/HttpClientProtocol.h"

namespace Netpp
{

// Pimpl: controls destruction order (reverse of member declaration)
struct Stack::Impl
{
  std::unique_ptr<EventLoop> loop;
  std::unique_ptr<Dispatcher> dispatcher;
  std::unique_ptr<Core::TimerHandler> timer;
  std::unique_ptr<Core::TcpHandler> tcp;
  std::unique_ptr<Core::UdpHandler> udp;
  std::unique_ptr<Dns::DnsProtocol> dns;
  std::unique_ptr<Http::HttpClientProtocol> httpClient;

  ~Impl()
  {
    // Explicit order: protocols -> transports -> timer -> dispatcher -> loop
    httpClient.reset();
    dns.reset();
    udp.reset();
    tcp.reset();
    timer.reset();
    dispatcher.reset();
    loop.reset();
  }
};

Stack::Stack(StackConfig config) : _config(std::move(config)), _impl(std::make_unique<Impl>())
{
  setupLogger();
}

Stack::~Stack()
{
  stop();
}

void Stack::setupLogger()
{
  if (_config.consoleLog)
  {
    auto handler = std::make_unique<Logger::LogHandlerSimple>(std::make_unique<Logger::LogFormatterSimple>(),
                                                              std::make_unique<Logger::LogWriterConsole>());
    Logger::Logger::getInstance()->addHandler(std::move(handler));
  }
  Logger::Logger::getInstance()->setLevel(_config.logLevel);
}

EventLoop &Stack::loop()
{
  if (!_impl->loop)
  {
    _impl->loop = std::make_unique<EventLoop>();
  }
  return *_impl->loop;
}

Dispatcher &Stack::dispatcher()
{
  if (!_impl->dispatcher)
  {
    if (_config.dispatcherType == StackConfig::DispatcherType::ThreadPool)
    {
      _impl->dispatcher = std::make_unique<Core::ThreadPoolDispatcher>(&loop(), _config.threadPoolSize);
    }
    else
    {
      _impl->dispatcher = std::make_unique<Core::SingleThreadDispatcher>(&loop());
    }
  }
  return *_impl->dispatcher;
}

TimerScheduler &Stack::timer()
{
  if (!_impl->timer)
  {
    _impl->timer = std::make_unique<Core::TimerHandler>(&loop());
  }
  return *_impl->timer;
}

Core::TcpHandler &Stack::tcp()
{
  if (!_impl->tcp)
  {
    _impl->tcp = std::make_unique<Core::TcpHandler>(&loop(), &dispatcher(), &timer(), &dns());
  }
  return *_impl->tcp;
}

Core::UdpHandler &Stack::udp()
{
  if (!_impl->udp)
  {
    _impl->udp = std::make_unique<Core::UdpHandler>(&loop(), &dispatcher());
  }
  return *_impl->udp;
}

Dns::DnsProtocol &Stack::dns()
{
  if (!_impl->dns)
  {
    _impl->dns = std::make_unique<Dns::DnsProtocol>(&udp(), &timer(), _config.dnsNameserver.c_str(), _config.dnsPort,
                                                    _config.dnsTimeout);
  }
  return *_impl->dns;
}

Http::HttpClientProtocol &Stack::httpClient()
{
  if (!_impl->httpClient)
  {
    _impl->httpClient = std::make_unique<Http::HttpClientProtocol>(&tcp());
  }
  return *_impl->httpClient;
}

void Stack::run()
{
  loop().run();
}

std::thread Stack::runInBackground()
{
  return std::thread([this]() { run(); });
}

void Stack::stop()
{
  if (_impl->loop)
  {
    _impl->loop->stop();
  }
  if (_impl->dispatcher)
  {
    _impl->dispatcher->stop();
  }
}

StackBuilder Stack::builder()
{
  return StackBuilder{};
}

// --- StackBuilder ---

StackBuilder &StackBuilder::singleThread()
{
  _config.dispatcherType = StackConfig::DispatcherType::SingleThread;
  return *this;
}

StackBuilder &StackBuilder::threadPool(size_t numThreads)
{
  _config.dispatcherType = StackConfig::DispatcherType::ThreadPool;
  _config.threadPoolSize = numThreads;
  return *this;
}

StackBuilder &StackBuilder::logLevel(Logger::LogLevel level)
{
  _config.logLevel = level;
  return *this;
}

StackBuilder &StackBuilder::noLog()
{
  _config.consoleLog = false;
  return *this;
}

StackBuilder &StackBuilder::dnsNameserver(const std::string &ns, uint16_t port)
{
  _config.dnsNameserver = ns;
  _config.dnsPort = port;
  return *this;
}

StackBuilder &StackBuilder::dnsTimeout(std::chrono::milliseconds timeout)
{
  _config.dnsTimeout = timeout;
  return *this;
}

Stack StackBuilder::build()
{
  return Stack(std::move(_config));
}

} // namespace Netpp
