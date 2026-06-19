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

  void listen(const std::string &ip, uint16_t port, Protocol *protocol)
  {
    logger(UDP, LogLevel::DEBUG, ip, port);
    auto addr = SockAddr::from(ip.c_str(), port);
    fd_t s = open(protocol, addr.family());
    Socket::bind(s, addr);
  }

  /// Open an unbound UDP socket for client use and register it for receiving.
  /// The OS assigns an ephemeral port on first sendto.
  fd_t open(Protocol *protocol, int family = AF_INET)
  {
    fd_t s = Socket::create(family, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP);
    logger(UDP, LogLevel::DEBUG, s);
    _listeners.emplace(s, protocol);
    _loop->add(s, this);
    return s;
  }

  void unregister(ConnectionPtr conn)
  {
    auto s = conn->getId();
    logger(UDP, LogLevel::DEBUG, s);
    auto lsi = _listeners.find(s);
    if (lsi != _listeners.end())
    {
      _listeners.erase(lsi);
      _loop->del(s);
      Socket::close(s);
    }
  }

  ConnectionPtr openConnection(Protocol *protocol)
  {
    fd_t s = open(protocol);
    return std::make_shared<Connection>(s, protocol, SockAddr{}, false);
  }

  ConnectionPtr createConnection(ConnectionPtr conn, Protocol *protocol, const std::string &peerAddr, uint16_t port)
  {
    auto addr = SockAddr::from(peerAddr.c_str(), port);
    return createConnection(conn->getId(), protocol, addr);
  }

  ConnectionPtr createConnection(fd_t s, Protocol *protocol, const SockAddr &peerAddr)
  {
    return std::make_shared<Connection>(s, protocol, peerAddr, false);
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

  void handle(fd_t s, LoopEventType t) override
  {
    switch (t)
    {
    case LoopEventType::READ:
      handleReading(s);
      break;
    case LoopEventType::WRITE:
    case LoopEventType::ERROR:
      break;
    }
  }

  void handleReading(fd_t s)
  {
    auto lsi = _listeners.find(s);
    if (lsi == _listeners.end())
    {
      logger(UDP, LogLevel::WARN, s, "unkn");
      return;
    }

    auto protocol = lsi->second;
    SockAddr addr;
    DataEvent data{DataEvent::Buffer(65536)};
    auto len = Socket::recvfrom(s, data.buffer.data(), data.buffer.size(), 0, addr);
    auto err = errno;

    logger(UDP, LogLevel::DEBUG, s, len);

    if (len > 0)
    {
      data.buffer.resize(static_cast<size_t>(len));
      auto conn = createConnection(s, protocol, addr);
      handleData(conn, std::move(data));
    }
    else if (len < 0 && err != EAGAIN && err != EWOULDBLOCK)
    {
      logger(UDP, LogLevel::ERROR, s, len, err, ::strerror(err));
    }
  }

  void send(ConnectionPtr conn, DataEvent data) override
  {
    if (data.buffer.empty())
    {
      return;
    }

    auto len = Socket::sendto(conn->getId(), data.buffer.data(), data.buffer.size(), 0, conn->getPeerAddr());
    auto err = errno;
    logger(UDP, LogLevel::DEBUG, conn->getId(), len);
    if (len < 0 && err != EAGAIN && err != EWOULDBLOCK)
    {
      logger(UDP, LogLevel::ERROR, conn->getId(), len, err, ::strerror(err));
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
  std::unordered_map<fd_t, Protocol *> _listeners;
};

} // namespace Netpp::Core
