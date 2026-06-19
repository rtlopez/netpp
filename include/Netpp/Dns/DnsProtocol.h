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
#include "Netpp/Resolver.h"
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
class DnsProtocol : public Protocol, public Resolver
{
public:
  static constexpr const char *DNS = "dns";

  DnsProtocol(Core::UdpHandler *handler, TimerScheduler *timer, const char *nameserver = "8.8.8.8", uint16_t port = 53,
              std::chrono::milliseconds queryTimeout = std::chrono::seconds(1))
      : _handler(handler), _timer(timer), _nameserver(nameserver), _port(port), _queryTimeout(queryTimeout),
        _rng(std::random_device{}())
  {
    if (!_handler || !_timer)
    {
      throw std::invalid_argument("DnsProtocol requires non-null udp handler and timer scheduler");
    }

    on(EventType::DATA, [this](ConnectionPtr conn, const DataEvent &data) { onData(conn, data); });
  }

  virtual ~DnsProtocol()
  {
    unregisterConnection();

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
        if (ctx->resolveCallback)
        {
          ctx->resolveCallback(std::string{});
        }
        else
        {
          ctx->promise.set_exception(std::make_exception_ptr(std::runtime_error("dns resolver stopped")));
        }
      }
    }
  }

  /// Resolve a domain name. Returns a future holding the full DNS response.
  /// The caller must ensure the event loop is running.
  std::future<DnsMessage> resolve(const std::string &name, DnsType type = DnsType::A)
  {
    ensureConnection();

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

  /// Resolver interface: resolve a hostname asynchronously via callback.
  /// On success, callback receives the resolved IP string.
  /// On failure (timeout, no records), callback receives an empty string.
  void resolve(const std::string &host, Resolver::Callback callback) override
  {
    ensureConnection();

    auto ctx = std::make_shared<QueryContext>();
    uint16_t id = 0;

    {
      std::lock_guard lock(_pendingMutex);
      id = generateIdLocked();
      _pending[id] = ctx;
    }

    auto msg = DnsMessage::query(host, DnsType::A, id);

    logger(DNS, LogLevel::DEBUG, "resolve:cb", host, id);

    ctx->name = host;
    ctx->type = DnsType::A;
    ctx->resolveCallback = std::move(callback);
    ctx->timerToken = _timer->scheduleTimer(_queryTimeout, [this, id]() { onTimeout(id); });

    auto wire = DnsParser::serialize(msg);
    sendQuery(std::move(wire));
  }

private:
  struct QueryContext
  {
    std::string name;
    DnsType type;
    std::promise<DnsMessage> promise;
    Resolver::Callback resolveCallback; // when set, callback-based resolve (Resolver interface)
    bool fulfilled = false;
    TimerScheduler::TimerToken timerToken = TimerScheduler::INVALID_TIMER;
  };

  void onTimeout(uint16_t id)
  {
    std::shared_ptr<QueryContext> ctx;
    bool lastQuery = false;

    {
      std::lock_guard lock(_pendingMutex);
      auto it = _pending.find(id);
      if (it == _pending.end())
      {
        return;
      }

      ctx = it->second;
      _pending.erase(it);
      lastQuery = _pending.empty();
    }

    if (!ctx->fulfilled)
    {
      logger(DNS, LogLevel::WARN, "timeout", id, ctx->name, typeToString(ctx->type));
      ctx->fulfilled = true;
      if (ctx->resolveCallback)
      {
        ctx->resolveCallback(std::string{});
      }
      else
      {
        ctx->promise.set_exception(
            std::make_exception_ptr(std::runtime_error("dns query timeout (connect or response)")));
      }
    }

    if (lastQuery)
    {
      unregisterConnection();
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
      bool lastQuery = false;

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
        lastQuery = _pending.empty();
      }

      if (ctx->timerToken != TimerScheduler::INVALID_TIMER)
      {
        _timer->cancelTimer(ctx->timerToken);
      }

      if (!ctx->fulfilled)
      {
        ctx->fulfilled = true;
        if (ctx->resolveCallback)
        {
          std::string ip;
          for (auto &answer : msg.answers)
          {
            if (answer.type == DnsType::A)
            {
              ip = answer.rdataAsIPv4();
              break;
            }
            if (answer.type == DnsType::AAAA)
            {
              ip = answer.rdataAsIPv6();
              break;
            }
          }
          ctx->resolveCallback(ip);
        }
        else
        {
          ctx->promise.set_value(std::move(msg));
        }
      }

      if (lastQuery)
      {
        unregisterConnection();
      }
    }
    catch (const DnsParseError &e)
    {
      logger(DNS, LogLevel::ERROR, e.what());
    }
  }

  void sendQuery(std::vector<uint8_t> wire)
  {
    auto conn = _handler->createConnection(_conn, this, _nameserver, _port);
    DataEvent data{.buffer = std::move(wire)};
    _handler->send(conn, std::move(data));

    logger(DNS, LogLevel::DEBUG, conn->getId());
  }

  void ensureConnection()
  {
    if (!_conn)
    {
      _conn = _handler->openConnection(this);
    }
  }

  void unregisterConnection()
  {
    if (_conn)
    {
      _handler->unregister(_conn);
      _conn.reset();
    }
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
  ConnectionPtr _conn;
  std::mt19937 _rng;

  std::mutex _pendingMutex;
  std::unordered_map<uint16_t, std::shared_ptr<QueryContext>> _pending;
};

} // namespace Netpp::Dns
