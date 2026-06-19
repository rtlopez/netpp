#pragma once

#include <chrono>
#include <memory>
#include <stdexcept>
#include <unordered_map>
#include <unordered_set>

#include <sys/eventfd.h>
#include <unistd.h>

#include "Netpp/MoveOnlyFunction.h"

#include "Netpp/Connection.h"
#include "Netpp/DataEvent.h"
#include "Netpp/Dispatcher.h"
#include "Netpp/EventLoop.h"
#include "Netpp/EventLoopHandler.h"
#include "Netpp/Logger/Logger.h"
#include "Netpp/Protocol.h"
#include "Netpp/Resolver.h"
#include "Netpp/Socket.h"
#include "Netpp/TimerScheduler.h"
#include "Netpp/TransportHandler.h"

namespace Netpp::Core
{
using Netpp::Logger::logger;
using Netpp::Logger::LogLevel;

class TcpHandler : public EventLoopHandler, public TransportHandler
{
public:
  static constexpr const char *TCP = "tcp";

  TcpHandler(EventLoop *loop, Dispatcher *dispatcher, TimerScheduler *timer, Resolver *resolver)
      : _loop(loop), _dispatcher(dispatcher), _timer(timer), _resolver(resolver)
  {
  }

  void listen(const char *ip, uint16_t port, Protocol *protocol)
  {
    logger(TCP, LogLevel::DEBUG, ip, port);
    auto addr = SockAddr::from(ip, port);
    auto s = Socket::create(addr.family(), SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);
    Socket::bind(s, addr);
    Socket::listen(s, 500);
    _listeners.emplace(s, protocol);
    _loop->add(s, this);
  }

  void connect(std::string host, uint16_t port, Protocol *protocol,
               std::chrono::milliseconds timeout = std::chrono::milliseconds{0},
               std::shared_ptr<void> context = nullptr)
  {
    if (timeout.count() > 0 && !_timer)
    {
      throw std::logic_error("TcpHandler connect requires Timer for timeout");
    }

    // If resolver is available and host is not a numeric IP, resolve asynchronously first
    if (!SockAddr::isValidIP(host.c_str()))
    {
      if (!_resolver)
      {
        throw std::logic_error("TcpHandler connect requires Resolver for non-numeric host");
      }
      logger(TCP, LogLevel::DEBUG, "connect:resolve", host, port);
      auto onResolved = [this, port, protocol, timeout, ctx = std::move(context)](std::string ip) {
        if (!ip.empty())
        {
          logger(TCP, LogLevel::DEBUG, "connect:resolved", ip, port);
          connectToAddress(ip, port, protocol, timeout, std::move(ctx));
        }
      };
      _resolver->resolve(std::move(host), std::move(onResolved));
      return;
    }

    connectToAddress(host, port, protocol, timeout, std::move(context));
  }

  virtual ~TcpHandler()
  {
    logger(TCP, LogLevel::DEBUG, _listeners.size());

    if (_timer)
    {
      for (auto &[s, token] : _connectTimeouts)
      {
        _timer->cancelTimer(token);
      }
      _connectTimeouts.clear();
    }

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
      handleWriting(s);
      break;
    case LoopEventType::ERROR:
      handleError(s);
      break;
    }
  }

  void handleError(fd_t s)
  {
    logger(TCP, LogLevel::DEBUG, s);
    _connecting.erase(s);
    cancelConnectTimeout(s);

    auto it = _connections.find(s);
    if (it != _connections.end())
    {
      auto conn = it->second;
      handleError(conn);
      handleDisconnect(conn);
    }

    close(s);
  }

  void handleReading(fd_t s)
  {
    auto lsi = _listeners.find(s);
    if (lsi != _listeners.end())
    {
      logger(TCP, LogLevel::DEBUG, s);
      auto protocol = lsi->second;
      SockAddr addr;
      auto as = Socket::accept(s, addr);
      if (as <= 0)
      {
        logger(TCP, LogLevel::ERROR, s, as, errno, ::strerror(errno));
        return;
      }
      auto conn = std::make_shared<Connection>(as, protocol, addr);
      _connections.emplace(as, conn);
      _loop->add(as, this);
      handleConnect(conn);
      return;
    }

    auto it = _connections.find(s);
    if (it != _connections.end())
    {
      auto conn = it->second;

      DataEvent data{DataEvent::Buffer(4096)};
      auto len = Socket::recv(s, data.buffer.data(), data.buffer.size(), 0);
      auto err = errno;

      logger(TCP, LogLevel::DEBUG, s, len);

      if (len > 0)
      {
        data.buffer.resize(static_cast<size_t>(len)); // set actual buffer size
        handleData(conn, std::move(data));
      }
      else if (len == 0)
      {
        logger(TCP, LogLevel::WARN, s, "closed by peer");
        handleDisconnect(conn);
        close(s);
      }
      else if (err == EAGAIN || err == EWOULDBLOCK)
      {
        // not ready, skip
      }
      else
      {
        logger(TCP, LogLevel::ERROR, s, len, err, ::strerror(err));
        handleDisconnect(conn);
        close(s);
      }
      return;
    }

    logger(TCP, LogLevel::WARN, s, "unkn");
  }

  void handleWriting(fd_t s)
  {
    logger(TCP, LogLevel::DEBUG, s, "begin");

    // check if this is a connecting socket completing async connect
    auto ci = _connecting.find(s);
    if (ci != _connecting.end())
    {
      _connecting.erase(ci);
      cancelConnectTimeout(s);

      int so_error = 0;
      socklen_t len = sizeof(so_error);
      ::getsockopt(s, SOL_SOCKET, SO_ERROR, &so_error, &len);

      if (so_error != 0)
      {
        logger(TCP, LogLevel::ERROR, s, so_error, ::strerror(so_error));
        auto it = _connections.find(s);
        if (it != _connections.end())
        {
          handleError(it->second);
        }
        close(s);
        return;
      }

      logger(TCP, LogLevel::DEBUG, "connect:ok", s);
      _loop->mod(s, false); // switch back to EPOLLIN only

      auto it = _connections.find(s);
      if (it != _connections.end())
      {
        handleConnect(it->second);
      }
      return;
    }

    auto it = _connections.find(s);
    if (it != _connections.end())
    {
      auto conn = it->second;
      DrainResult result =
          _dispatcher->drain(conn, [this](ConnectionPtr conn, DataEvent &data) { return sendNow(conn, data); });

      logger(TCP, LogLevel::DEBUG, s, to_string(result));

      if (result == DrainResult::Close)
      {
        close(s);
        return;
      }

      _dispatcher->runGenerator(conn);

      return;
    }

    logger(TCP, LogLevel::WARN, s, "unkn");
  }

  void send(ConnectionPtr conn, MoveOnlyFunction<DataEvent(void)> generator) override
  {
    _dispatcher->send(conn, std::move(generator));
  }

  void send(ConnectionPtr conn, DataEvent data) override
  {
    _dispatcher->send(conn, std::move(data));
  }

private:
  void connectToAddress(const std::string &ip, uint16_t port, Protocol *protocol, std::chrono::milliseconds timeout,
                        std::shared_ptr<void> context)
  {
    logger(TCP, LogLevel::DEBUG, "connect", ip, port);
    auto addr = SockAddr::from(ip.c_str(), port);
    auto s = Socket::create(addr.family(), SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);
    Socket::connect(s, addr);

    auto conn = std::make_shared<Connection>(s, protocol, std::move(addr));
    if (context)
    {
      conn->setContext(std::move(context));
    }
    _connections.emplace(s, conn);

    if (_timer && timeout.count() > 0)
    {
      auto token = _timer->scheduleTimer(timeout, [this, s]() { onConnectTimeout(s); });
      if (token != TimerScheduler::INVALID_TIMER)
      {
        _connectTimeouts.emplace(s, token);
      }
    }

    // EINPROGRESS or immediate - register for EPOLLOUT to detect connect completion
    _connecting.emplace(s);
    _loop->add(s, this);
    _loop->mod(s, true);

    handleResolved(conn);
  }

  void handleResolved(ConnectionPtr conn)
  {
    if (conn->getProtocol()->hasHandler(Netpp::EventType::RESOLVED))
    {
      DataEvent data{.eventType = Netpp::EventType::RESOLVED};
      ConnectionWeakPtr weak{conn};
      _dispatcher->post(conn, [weak, data = std::move(data)]() mutable {
        if (auto conn = weak.lock())
        {
          conn->getProtocol()->handle(conn, std::move(data));
        }
      });
    }
  }

  void handleConnect(ConnectionPtr conn)
  {
    if (conn->getProtocol()->hasHandler(Netpp::EventType::CONNECT))
    {
      DataEvent data{.eventType = Netpp::EventType::CONNECT};
      ConnectionWeakPtr weak{conn};
      _dispatcher->post(conn, [weak, data = std::move(data)]() mutable {
        if (auto conn = weak.lock())
        {
          conn->getProtocol()->handle(conn, std::move(data));
        }
      });
    }
  }

  void handleDisconnect(ConnectionPtr conn)
  {
    conn->setClosed(true);
    if (conn->getProtocol()->hasHandler(Netpp::EventType::DISCONNECT))
    {
      DataEvent data{.eventType = Netpp::EventType::DISCONNECT};
      _dispatcher->post(
          conn, [conn, data = std::move(data)]() mutable { conn->getProtocol()->handle(conn, std::move(data)); });
    }
  }

  void handleData(ConnectionPtr conn, DataEvent data)
  {
    if (conn->getProtocol()->hasHandler(Netpp::EventType::DATA))
    {
      ConnectionWeakPtr weak{conn};
      _dispatcher->post(conn, [weak, data = std::move(data)]() mutable {
        if (auto conn = weak.lock())
        {
          conn->getProtocol()->handle(conn, std::move(data));
        }
      });
    }
  }

  void handleError(ConnectionPtr conn)
  {
    if (conn->getProtocol()->hasHandler(Netpp::EventType::ERROR))
    {
      DataEvent data{.eventType = Netpp::EventType::ERROR};
      ConnectionWeakPtr weak{conn};
      _dispatcher->post(conn, [weak, data = std::move(data)]() mutable {
        if (auto conn = weak.lock())
        {
          conn->getProtocol()->handle(conn, std::move(data));
        }
      });
    }
  }

  void handleTimeout(ConnectionPtr conn)
  {
    if (conn->getProtocol()->hasHandler(Netpp::EventType::TIMEOUT))
    {
      DataEvent data{.eventType = Netpp::EventType::TIMEOUT};
      ConnectionWeakPtr weak{conn};
      _dispatcher->post(conn, [weak, data = std::move(data)]() mutable {
        if (auto conn = weak.lock())
        {
          conn->getProtocol()->handle(conn, std::move(data));
        }
      });
    }
  }

  bool sendNow(ConnectionPtr conn, DataEvent &data)
  {
    if (data.buffer.empty())
    {
      return true;
    }

    do
    {
      auto len = Socket::send(conn->getId(), data.buffer.data() + data.sent, data.buffer.size() - data.sent, 0);
      auto err = errno;
      logger(TCP, LogLevel::DEBUG, conn->getId(), len, (size_t)data.eventType);
      if (len < 0)
      {
        if (err == EAGAIN || err == EWOULDBLOCK)
        {
          // unable to drain connection buffer, wait for next writable event
          return false;
        }
        logger(TCP, LogLevel::ERROR, conn->getId(), len, err, ::strerror(err));
        data.eventType = EventType::DISCONNECT; // mark for error
        data.sent = data.buffer.size();         // mark as "done" so error triggers
        return true;
      }
      else
      {
        data.sent += static_cast<size_t>(len);
      }
    } while (data.sent < data.buffer.size());
    return true;
  }

  void close(fd_t s)
  {
    logger(TCP, LogLevel::DEBUG, s);
    _connecting.erase(s);
    cancelConnectTimeout(s);
    _loop->del(s); // remove from epoll before closing the fd
    auto it = _connections.find(s);
    if (it != _connections.end())
    {
      _connections.erase(it); // Connection destructor closes the fd
    }
  }

  void onConnectTimeout(fd_t s)
  {
    auto ci = _connecting.find(s);
    if (ci == _connecting.end())
    {
      cancelConnectTimeout(s);
      return;
    }

    _connecting.erase(ci);
    cancelConnectTimeout(s);

    logger(TCP, LogLevel::WARN, "connect:timeout", s);

    auto it = _connections.find(s);
    if (it != _connections.end())
    {
      handleTimeout(it->second);
    }

    close(s);
  }

  void cancelConnectTimeout(fd_t s)
  {
    auto it = _connectTimeouts.find(s);
    if (it == _connectTimeouts.end())
    {
      return;
    }

    _timer->cancelTimer(it->second);
    _connectTimeouts.erase(it);
  }

  EventLoop *_loop;
  Dispatcher *_dispatcher;
  TimerScheduler *_timer;
  Resolver *_resolver;
  std::unordered_map<fd_t, Protocol *> _listeners;
  std::unordered_map<fd_t, ConnectionPtr> _connections;
  std::unordered_map<fd_t, TimerScheduler::TimerToken> _connectTimeouts;
  std::unordered_set<fd_t> _connecting; // sockets with async connect in progress
};

} // namespace Netpp::Core
