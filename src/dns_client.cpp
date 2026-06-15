#include <future>
#include <iostream>
#include <string>
#include <thread>
#include <unistd.h>

#include "Netpp/Core/SingleThreadDispatcher.h"
#include "Netpp/Core/TimerHandler.h"
#include "Netpp/Core/UdpHandler.h"
#include "Netpp/Dns/DnsMessage.h"
#include "Netpp/Dns/DnsProtocol.h"
#include "Netpp/EventLoopEpoll.h"
#include "Netpp/Logger/Logger.h"
#include "Netpp/SignalHandler.h"

int main(int argc, char *argv[])
{
  const char *name = argc > 1 ? argv[1] : "example.com";
  const char *record = argc > 2 ? argv[2] : "a";
  const char *ns = argc > 3 ? argv[3] : "127.0.0.53";

  auto stringToDnsType = [](const std::string &typeStr) -> Netpp::Dns::DnsType {
    std::string lower = typeStr;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

    // clang-format off
    if (lower == "a") return Netpp::Dns::DnsType::A;
    if (lower == "aaaa") return Netpp::Dns::DnsType::AAAA;
    if (lower == "cname") return Netpp::Dns::DnsType::CNAME;
    if (lower == "mx") return Netpp::Dns::DnsType::MX;
    if (lower == "ns") return Netpp::Dns::DnsType::NS;
    if (lower == "txt") return Netpp::Dns::DnsType::TXT;
    if (lower == "soa") return Netpp::Dns::DnsType::SOA;
    if (lower == "ptr") return Netpp::Dns::DnsType::PTR;
    if (lower == "srv") return Netpp::Dns::DnsType::SRV;
    return Netpp::Dns::DnsType::A; // default to A
    // clang-format on
  };

  Netpp::Dns::DnsType type = stringToDnsType(record);

  auto logHandler = std::make_unique<Netpp::Logger::LogHandlerSimple>(
      std::make_unique<Netpp::Logger::LogFormatterSimple>(), std::make_unique<Netpp::Logger::LogWriterConsole>());
  Netpp::Logger::Logger::getInstance()->addHandler(std::move(logHandler));
  Netpp::Logger::Logger::getInstance()->setLevel(Netpp::Logger::LogLevel::WARN);

  Netpp::EventLoopEpoll loop{};
  Netpp::LoopControlHandler loopControl{&loop};
  Netpp::SignalHandler signals{&loop, &loopControl, {SIGINT, SIGTERM}};
  Netpp::Core::TimerHandler timer{&loop};
  Netpp::Core::SingleThreadDispatcher dispatcher{&loop};
  Netpp::Core::UdpHandler udpHandler{&loop, &dispatcher};

  Netpp::Dns::DnsProtocol dns{&udpHandler, &timer, ns};

  auto start = std::chrono::steady_clock::now();
  auto future = dns.resolve(name, type);

  std::thread loopThread([&loop]() { loop.run(); });

  auto status = future.wait_for(std::chrono::seconds(5));
  if (status == std::future_status::ready)
  {
    try
    {
      auto response = future.get();

      std::cout << "DNS response for: " << name << "\n";
      std::cout << "Status: " << Netpp::Dns::rcodeToString(response.header.rcode) << ", ";
      std::cout << "Answers: " << response.answers.size() << "\n";

      size_t nameLen = 8;
      for (const auto &answer : response.answers)
      {
        nameLen = std::max(nameLen, answer.name.size());
      }

      for (const auto &answer : response.answers)
      {
        std::cout << std::setw(nameLen + 2) << std::right << answer.name << "  " << answer.ttl << "  "
                  << Netpp::Dns::classToString(answer.cls) << "  " << std::setw(5)
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
    catch (const std::exception &e)
    {
      std::cerr << "DNS query failed: " << e.what() << "\n";
    }
  }
  else
  {
    std::cerr << "DNS query timed out\n";
  }

  auto end = std::chrono::steady_clock::now();
  auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
  std::cout << "Query time: " << duration.count() << " ms, Server: " << ns << "\n";

  loopControl.stop();
  loopThread.join();
  dispatcher.stop();

  return 0;
}
