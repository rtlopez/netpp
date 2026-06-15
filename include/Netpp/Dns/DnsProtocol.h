#pragma once

#include <chrono>
#include <exception>
#include <future>
#include <memory>
#include <mutex>
#include <random>
#include <stdexcept>
#include <string>
#include <unordered_map>

#include "Netpp/Connection.h"
#include "Netpp/Core/UdpHandler.h"
#include "Netpp/DataEvent.h"
#include "Netpp/Dns/DnsMessage.h"
#include "Netpp/Dns/DnsParser.h"
#include "Netpp/Logger/Logger.h"
#include "Netpp/Protocol.h"
#include "Netpp/TimerScheduler.h"

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
///   DnsProtocol dns{&udpHandler, &timer, "8.8.8.8"};
///   auto future = dns.resolve("example.com");
///   // ... event loop running ...
///   DnsMessage response = future.get();
///   for (auto &a : response.answers) { ... }
class DnsProtocol : public Protocol
{
public:
  static constexpr const char *DNS = "dns";

  DnsProtocol(Core::UdpHandler *handler, TimerScheduler *timer, const char *nameserver = "8.8.8.8", uint16_t port = 53,
              std::chrono::milliseconds queryTimeout = std::chrono::seconds(5))
      : _handler(handler), _timer(timer), _nameserver(nameserver), _port(port), _queryTimeout(queryTimeout),
        _rng(std::random_device{}())
  {
    if (!_handler || !_timer)
    {
      throw std::invalid_argument("DnsProtocol requires non-null udp handler and timer scheduler");
    }

    on(DATA, [this](ConnectionPtr conn, const DataEvent &data) { onData(conn, data); });
    _sock = _handler->open(this);
  }

  virtual ~DnsProtocol()
  {
    _handler->unregister(_sock);

    std::unordered_map<uint16_t, std::shared_ptr<QueryContext>> pending;
    {
      std::lock_guard lock(_pendingMutex);
      pending.swap(_pending);
    }

    for (auto &[id, ctx] : pending)
    {
      if (ctx->timerToken != TimerScheduler::INVALID_TIMER)
      {
        _timer->cancelTimer(ctx->timerToken);
      }

      if (!ctx->fulfilled)
      {
        ctx->fulfilled = true;
        ctx->promise.set_exception(std::make_exception_ptr(std::runtime_error("dns resolver stopped")));
      }
    }
  }

  /// Resolve a domain name. Returns a future holding the full DNS response.
  /// The caller must ensure the event loop is running.
  std::future<DnsMessage> resolve(const std::string &name, DnsType type = DnsType::A)
  {
    auto ctx = std::make_shared<QueryContext>();
    uint16_t id = 0;

    {
      std::lock_guard lock(_pendingMutex);
      id = generateIdLocked();
      _pending[id] = ctx;
    }

    auto msg = DnsMessage::query(name, type, id);

    logger(DNS, LogLevel::DEBUG, name, typeToString(type), id);

    ctx->name = name;
    ctx->type = type;
    auto future = ctx->promise.get_future();
    ctx->timerToken = _timer->scheduleTimer(_queryTimeout, [this, id]() { onTimeout(id); });

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
    TimerScheduler::TimerToken timerToken = TimerScheduler::INVALID_TIMER;
  };

  void onTimeout(uint16_t id)
  {
    std::shared_ptr<QueryContext> ctx;

    {
      std::lock_guard lock(_pendingMutex);
      auto it = _pending.find(id);
      if (it == _pending.end())
      {
        return;
      }

      ctx = it->second;
      _pending.erase(it);
    }

    if (!ctx->fulfilled)
    {
      logger(DNS, LogLevel::WARN, "timeout", id, ctx->name, typeToString(ctx->type));
      ctx->fulfilled = true;
      ctx->promise.set_exception(
          std::make_exception_ptr(std::runtime_error("dns query timeout (connect or response)")));
    }
  }

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

      if (ctx->timerToken != TimerScheduler::INVALID_TIMER)
      {
        _timer->cancelTimer(ctx->timerToken);
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

  uint16_t generateIdLocked()
  {
    if (_pending.size() >= 0xFFFF)
    {
      throw std::runtime_error("too many pending dns queries");
    }

    std::uniform_int_distribution<uint16_t> dist(1, 0xFFFF);
    for (;;)
    {
      auto id = dist(_rng);
      if (_pending.find(id) == _pending.end())
      {
        return id;
      }
    }
  }

  Core::UdpHandler *_handler;
  TimerScheduler *_timer;
  const char *_nameserver;
  uint16_t _port;
  std::chrono::milliseconds _queryTimeout;
  sock_t _sock = -1;
  std::mt19937 _rng;

  std::mutex _pendingMutex;
  std::unordered_map<uint16_t, std::shared_ptr<QueryContext>> _pending;
};

} // namespace Netpp::Dns
