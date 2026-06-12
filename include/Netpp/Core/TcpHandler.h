#pragma once

#include <memory>
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
#include "Netpp/Socket.h"

namespace Netpp::Core
{
using Netpp::Logger::logger;
using Netpp::Logger::LogLevel;

class TcpHandler : public EventLoopHandler
{
public:
  static constexpr const char *TCP = "tcp";

  TcpHandler(EventLoop *loop, Dispatcher *dispatcher) : _loop(loop), _dispatcher(dispatcher)
  {
  }

  void listen(const char *addr, uint16_t port, Protocol *protocol)
  {
    logger(TCP, LogLevel::DEBUG, addr, port);
    sock_t s = Socket::create(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);
    Socket::bind(s, addr, port);
    Socket::listen(s, 500);
    _listeners.emplace(s, protocol);
    _loop->add(s, this);
  }

  ConnectionWeakPtr connect(const char *host, uint16_t port, Protocol *protocol)
  {
    logger(TCP, LogLevel::DEBUG, "connect", host, port);
    sock_t s = Socket::create(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);
    int ret = Socket::connect(s, host, port);

    auto conn = std::make_shared<Connection>(s, protocol);
    _connections.emplace(s, conn);

    if (ret == 0)
    {
      // immediate connect (rare for non-blocking)
      _loop->add(s, this);
      handleConnect(conn);
    }
    else
    {
      // EINPROGRESS - wait for writable event to confirm connection
      _connecting.emplace(s);
      _loop->add(s, this);
      _loop->mod(s, true); // enable EPOLLOUT to detect connect completion
    }

    return conn;
  }

  virtual ~TcpHandler()
  {
    logger(TCP, LogLevel::DEBUG, _listeners.size());
    for (auto &[s, protocol] : _listeners)
    {
      _loop->del(s);
      Socket::close(s);
    }
  }

  void handleError(sock_t s) override
  {
    logger(TCP, LogLevel::DEBUG, s);
    _connecting.erase(s);

    auto it = _connections.find(s);
    if (it != _connections.end())
    {
      auto conn = it->second;
      handleError(conn);
      handleDisconnect(conn);
    }

    close(s);
  }

  void handleReading(sock_t s) override
  {
    auto lsi = _listeners.find(s);
    if (lsi != _listeners.end())
    {
      logger(TCP, LogLevel::DEBUG, "accept", s);
      auto protocol = lsi->second;
      sockaddr_in addr;
      sock_t as = Socket::accept(s, addr);
      if (as <= 0)
      {
        logger(TCP, LogLevel::ERROR, "accept:error", s, as, errno, ::strerror(errno));
        return;
      }
      auto conn = std::make_shared<Connection>(as, protocol);
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

      logger(TCP, LogLevel::DEBUG, "recv", s, len);

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
        logger(TCP, LogLevel::ERROR, "recv:error", s, len, err, ::strerror(err));
        handleDisconnect(conn);
        close(s);
      }
      return;
    }

    logger(TCP, LogLevel::WARN, "unknown", s);
  }

  void handleWriting(sock_t s) override
  {
    logger(TCP, LogLevel::DEBUG, s, "begin");

    // check if this is a connecting socket completing async connect
    auto ci = _connecting.find(s);
    if (ci != _connecting.end())
    {
      _connecting.erase(ci);

      int so_error = 0;
      socklen_t len = sizeof(so_error);
      ::getsockopt(s, SOL_SOCKET, SO_ERROR, &so_error, &len);

      if (so_error != 0)
      {
        logger(TCP, LogLevel::ERROR, "connect:failed", s, so_error, ::strerror(so_error));
        close(s);
        return;
      }

      logger(TCP, LogLevel::DEBUG, "connect:ok", s);
      _loop->mod(s, false); // switch back to EPOLLIN only

      auto it = _connections.find(s);
      if (it != _connections.end())
      {
        auto conn = it->second;
        handleConnect(conn);
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

    logger(TCP, LogLevel::WARN, s, "unknown");
  }

  void send(ConnectionPtr conn, MoveOnlyFunction<DataEvent(void)> generator)
  {
    _dispatcher->send(conn, std::move(generator));
  }

  void send(ConnectionPtr conn, DataEvent data)
  {
    _dispatcher->send(conn, std::move(data));
  }

private:
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
      logger(TCP, LogLevel::DEBUG, conn->getId(), len, data.eventType);
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

  void close(sock_t s)
  {
    logger(TCP, LogLevel::DEBUG, s);
    _connecting.erase(s);
    _loop->del(s); // remove from epoll before closing the fd
    auto it = _connections.find(s);
    if (it != _connections.end())
    {
      _connections.erase(it); // Connection destructor closes the fd
    }
  }

  EventLoop *_loop;
  Dispatcher *_dispatcher;
  std::unordered_map<sock_t, Protocol *> _listeners;
  std::unordered_map<sock_t, ConnectionPtr> _connections;
  std::unordered_set<sock_t> _connecting; // sockets with async connect in progress
};

} // namespace Netpp::Core
