#pragma once

#include <future>
#include <memory>
#include <mutex>
#include <random>
#include <string>
#include <unordered_map>

#include "Netpp/Connection.h"
#include "Netpp/Core/UdpHandler.h"
#include "Netpp/DataEvent.h"
#include "Netpp/Dns/DnsMessage.h"
#include "Netpp/Dns/DnsParser.h"
#include "Netpp/Logger/Logger.h"
#include "Netpp/Protocol.h"

namespace Netpp::Dns
{
using Logger::logger;
using Logger::LogLevel;

/// DNS client protocol over UDP.
///
/// Sends DNS queries and resolves responses asynchronously via std::future.
/// Designed for use as a building block for name resolution in higher-level
/// protocols (e.g. HTTP).
///
/// Usage:
///   DnsProtocol dns{&udpHandler, "8.8.8.8"};
///   auto future = dns.resolve("example.com");
///   // ... event loop running ...
///   DnsMessage response = future.get();
///   for (auto &a : response.answers) { ... }
class DnsProtocol : public Protocol
{
public:
  static constexpr const char *DNS = "dns";

  DnsProtocol(Core::UdpHandler *handler, const char *nameserver = "8.8.8.8", uint16_t port = 53)
      : _handler(handler), _nameserver(nameserver), _port(port), _rng(std::random_device{}())
  {
    on(DATA, [this](ConnectionPtr conn, const DataEvent &data) { onData(conn, data); });
    _sock = _handler->open(this);
  }

  virtual ~DnsProtocol()
  {
  }

  /// Resolve a domain name. Returns a future holding the full DNS response.
  /// The caller must ensure the event loop is running.
  std::future<DnsMessage> resolve(const std::string &name, DnsType type = DnsType::A)
  {
    uint16_t id = generateId();
    auto msg = DnsMessage::query(name, type, id);

    logger(DNS, LogLevel::DEBUG, name, typeToString(type), id);

    auto ctx = std::make_shared<QueryContext>();
    ctx->name = name;
    ctx->type = type;
    auto future = ctx->promise.get_future();

    {
      std::lock_guard lock(_pendingMutex);
      _pending[id] = ctx;
    }

    auto wire = DnsParser::serialize(msg);
    sendQuery(std::move(wire));

    return future;
  }

private:
  struct QueryContext
  {
    std::string name;
    DnsType type;
    std::promise<DnsMessage> promise;
    bool fulfilled = false;
  };

  void onData(ConnectionPtr /*conn*/, const DataEvent &data)
  {
    if (data.buffer.size() < 12)
    {
      logger(DNS, LogLevel::WARN, "short packet", data.buffer.size());
      return;
    }

    try
    {
      auto msg = DnsParser::parse(data.buffer.data(), data.buffer.size());
      logger(DNS, LogLevel::DEBUG, "response", msg.header.id, rcodeToString(msg.header.rcode), msg.header.ancount);

      std::shared_ptr<QueryContext> ctx;
      {
        std::lock_guard lock(_pendingMutex);
        auto it = _pending.find(msg.header.id);
        if (it == _pending.end())
        {
          logger(DNS, LogLevel::WARN, "unexpected id", msg.header.id);
          return;
        }
        ctx = it->second;
        _pending.erase(it);
      }

      if (!ctx->fulfilled)
      {
        ctx->fulfilled = true;
        ctx->promise.set_value(std::move(msg));
      }
    }
    catch (const DnsParseError &e)
    {
      logger(DNS, LogLevel::ERROR, e.what());
    }
  }

  void sendQuery(std::vector<uint8_t> wire)
  {
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(_port);
    addr.sin_addr.s_addr = inet_addr(_nameserver);

    auto conn = std::make_shared<Connection>(_sock, this, addr, false);
    DataEvent ev{.buffer = std::move(wire)};
    _handler->send(conn, std::move(ev));

    logger(DNS, LogLevel::DEBUG, _sock);
  }

  uint16_t generateId()
  {
    std::uniform_int_distribution<uint16_t> dist(1, 0xFFFF);
    return dist(_rng);
  }

  Core::UdpHandler *_handler;
  const char *_nameserver;
  uint16_t _port;
  sock_t _sock = -1;
  std::mt19937 _rng;

  std::mutex _pendingMutex;
  std::unordered_map<uint16_t, std::shared_ptr<QueryContext>> _pending;
};

} // namespace Netpp::Dns
