#pragma once

#include <memory>
#include <unordered_map>

#include "Netpp/MoveOnlyFunction.h"

#include "Netpp/Connection.h"
#include "Netpp/DataEvent.h"
#include "Netpp/Dispatcher.h"
#include "Netpp/EventLoop.h"
#include "Netpp/EventLoopHandler.h"
#include "Netpp/Logger/Logger.h"
#include "Netpp/Protocol.h"
#include "Netpp/Socket.h"
#include "Netpp/TransportHandler.h"

namespace Netpp::Core
{
using Netpp::Logger::logger;
using Netpp::Logger::LogLevel;

class UdpHandler : public EventLoopHandler, public TransportHandler
{
public:
  static constexpr const char *UDP = "udp";

  UdpHandler(EventLoop *loop, Dispatcher *dispatcher) : _loop(loop), _dispatcher(dispatcher)
  {
  }

  void listen(const char *addr, uint16_t port, Protocol *protocol)
  {
    logger(UDP, LogLevel::DEBUG, addr, port);
    sock_t s = Socket::create(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP);
    Socket::bind(s, addr, port);
    _listeners.emplace(s, protocol);
    _loop->add(s, this);
  }

  /// Register a pre-created socket with the event loop for receiving.
  void listen(sock_t s, Protocol *protocol)
  {
    logger(UDP, LogLevel::DEBUG, s);
    _listeners.emplace(s, protocol);
    _loop->add(s, this);
  }

  /// Open an unbound UDP socket for client use and register it for receiving.
  /// The OS assigns an ephemeral port on first sendto.
  sock_t open(Protocol *protocol)
  {
    sock_t s = Socket::create(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP);
    logger(UDP, LogLevel::DEBUG, s);
    _listeners.emplace(s, protocol);
    _loop->add(s, this);
    return s;
  }

  virtual ~UdpHandler()
  {
    logger(UDP, LogLevel::DEBUG, _listeners.size());
    for (auto &[s, protocol] : _listeners)
    {
      _loop->del(s);
      Socket::close(s);
    }
  }

  void handleError(sock_t s) override
  {
    logger(UDP, LogLevel::ERROR, s);
  }

  void handleReading(sock_t s) override
  {
    auto lsi = _listeners.find(s);
    if (lsi == _listeners.end())
    {
      logger(UDP, LogLevel::WARN, s, "unknown");
      return;
    }

    auto protocol = lsi->second;
    sockaddr_in addr;
    DataEvent data{DataEvent::Buffer(65536)};
    auto len = Socket::recvfrom(s, data.buffer.data(), data.buffer.size(), 0, addr);
    auto err = errno;

    logger(UDP, LogLevel::DEBUG, s, "recvfrom", len);

    if (len > 0)
    {
      data.buffer.resize(static_cast<size_t>(len));
      auto conn = std::make_shared<Connection>(s, protocol, addr, false);
      handleData(conn, std::move(data));
    }
    else if (len < 0 && err != EAGAIN && err != EWOULDBLOCK)
    {
      logger(UDP, LogLevel::ERROR, s, "recvfrom:error", len, err, ::strerror(err));
    }
  }

  void handleWriting(sock_t) override
  {
  }

  void send(ConnectionPtr conn, DataEvent data) override
  {
    if (data.buffer.empty())
    {
      return;
    }

    auto len = Socket::sendto(conn->getId(), data.buffer.data(), data.buffer.size(), 0, conn->getPeerAddr());
    auto err = errno;
    logger(UDP, LogLevel::DEBUG, conn->getId(), "sendto", len);
    if (len < 0 && err != EAGAIN && err != EWOULDBLOCK)
    {
      logger(UDP, LogLevel::ERROR, conn->getId(), "sendto:error", len, err, ::strerror(err));
    }
  }

  void send(ConnectionPtr conn, MoveOnlyFunction<DataEvent(void)> generator) override
  {
    send(conn, generator());
  }

private:
  void handleData(ConnectionPtr conn, DataEvent data)
  {
    if (conn->getProtocol()->hasHandler(Netpp::EventType::DATA))
    {
      _dispatcher->post(
          [conn, data = std::move(data)]() mutable { conn->getProtocol()->handle(conn, std::move(data)); });
    }
  }

  EventLoop *_loop;
  Dispatcher *_dispatcher;
  std::unordered_map<sock_t, Protocol *> _listeners;
};

} // namespace Netpp::Core
