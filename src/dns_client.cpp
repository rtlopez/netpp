#include <future>
#include <iostream>
#include <string>
#include <thread>
#include <unistd.h>

#include "Netpp/Core/SingleThreadDispatcher.h"
#include "Netpp/Core/UdpHandler.h"
#include "Netpp/Dns/DnsMessage.h"
#include "Netpp/Dns/DnsProtocol.h"
#include "Netpp/EventLoopEpoll.h"
#include "Netpp/Logger/Logger.h"
#include "Netpp/SignalHandler.h"

int main(int argc, char *argv[])
{
  const char *name = argc > 1 ? argv[1] : "example.com";
  const char *ns = argc > 2 ? argv[2] : "8.8.8.8";

  auto logHandler = std::make_unique<Netpp::Logger::LogHandlerSimple>(
      std::make_unique<Netpp::Logger::LogFormatterSimple>(), std::make_unique<Netpp::Logger::LogWriterConsole>());
  Netpp::Logger::Logger::getInstance()->addHandler(std::move(logHandler));
  Netpp::Logger::Logger::getInstance()->setLevel(Netpp::Logger::LogLevel::WARN);

  Netpp::EventLoopEpoll loop;
  Netpp::SignalHandler signals{&loop, {SIGINT, SIGTERM}};
  Netpp::Core::SingleThreadDispatcher dispatcher{&loop};
  Netpp::Core::UdpHandler udpHandler{&loop, &dispatcher};

  Netpp::Dns::DnsProtocol dns{&udpHandler, ns};

  auto start = std::chrono::steady_clock::now();
  auto future = dns.resolve(name, Netpp::Dns::DnsType::A);

  std::thread loopThread([&loop]() { loop.run(); });

  auto status = future.wait_for(std::chrono::seconds(5));
  if (status == std::future_status::ready)
  {
    auto response = future.get();

    std::cout << "DNS response for: " << name << "\n";
    std::cout << "  Status: " << Netpp::Dns::rcodeToString(response.header.rcode) << "\n";
    std::cout << "  Answers: " << response.answers.size() << "\n";

    for (const auto &answer : response.answers)
    {
      std::cout << "  " << answer.name << "  " << answer.ttl << "  " << Netpp::Dns::classToString(answer.cls) << "  "
                << Netpp::Dns::typeToString(answer.type);
      if (answer.type == Netpp::Dns::DnsType::A)
      {
        std::cout << "  " << answer.rdataAsIPv4();
      }
      else if (answer.type == Netpp::Dns::DnsType::AAAA)
      {
        std::cout << "  " << answer.rdataAsIPv6();
      }
      else if (answer.type == Netpp::Dns::DnsType::CNAME)
      {
        std::cout << "  " << answer.rdataAsName();
      }
      std::cout << "\n";
    }
  }
  else
  {
    std::cerr << "DNS query timed out\n";
  }

  auto end = std::chrono::steady_clock::now();
  auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
  std::cout << "Query time: " << duration.count() << " ms\n";

  loop.stop();
  loopThread.join();
  dispatcher.stop();

  return 0;
}
