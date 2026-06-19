#include <iostream>
#include <string>

#include "Netpp/Dns/DnsMessage.h"
#include "Netpp/Dns/DnsProtocol.h"
#include "Netpp/Stack.h"

int main(int argc, char *argv[])
{
  std::set_terminate(netpp_terminate_handler);

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

  Netpp::Stack stack({.logLevel = Netpp::Logger::LogLevel::WARN, .dnsNameserver = ns});

  auto start = std::chrono::steady_clock::now();
  auto future = stack.dns().resolve(name, type);

  stack.run(); // blocks until query completes (socket auto-unregisters)

  try
  {
    auto response = future.get();

    std::cout << "DNS response for: " << name << ", ";
    std::cout << "Status: " << Netpp::Dns::rcodeToString(response.header.rcode) << "\n\n";
    std::cout << "Answers(" << response.answers.size() << "):\n";

    size_t nameLen = 1;
    for (const auto &answer : response.answers)
    {
      nameLen = std::max(nameLen, answer.name.size());
    }
    nameLen++;

    for (const auto &answer : response.answers)
    {
      std::cout << std::setw(nameLen) << std::right << answer.name << "  ";
      std::cout << answer.ttl << "  " << Netpp::Dns::classToString(answer.cls) << "  ";
      std::cout << std::setw(5) << Netpp::Dns::typeToString(answer.type) << "  " << answer.rdataString << "\n";
    }
  }
  catch (const std::exception &e)
  {
    std::cerr << "Error: " << e.what() << "\n";
  }

  auto end = std::chrono::steady_clock::now();
  auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
  std::cout << "\nQuery time: " << duration.count() << " ms, Server: " << ns << "\n";

  return 0;
}
