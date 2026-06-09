#pragma once

#include <memory>
#include <unordered_map>

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

namespace Netpp
{

using Netpp::Logger::logger;
using Netpp::Logger::LogLevel;
static const char *TCPSERVER = "tcpserver";

class TcpServer : public EventLoopHandler
{
public:
  TcpServer(EventLoop *loop, Dispatcher *dispatcher) : _loop(loop), _dispatcher(dispatcher)
  {
  }

  void listen(const char *addr, uint16_t port, Protocol *protocol)
  {
    logger(TCPSERVER, LogLevel::DEBUG).log(addr, port);
    sock_t s = Socket::create(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);
    Socket::bind(s, addr, port);
    Socket::listen(s, 128);
    _listeners.emplace(s, protocol);
    _loop->add(s, this);
  }

  virtual ~TcpServer()
  {
    logger(TCPSERVER, LogLevel::DEBUG).log(_listeners.size());
    for (auto &[s, protocol] : _listeners)
    {
      _loop->del(s);
      Socket::close(s);
    }
  }

  virtual void handleError(sock_t s) override
  {
    close(s);
  }

  virtual void handleReading(sock_t s) override
  {
    auto lsi = _listeners.find(s);
    if (lsi != _listeners.end())
    {
      logger(TCPSERVER, LogLevel::DEBUG).log("accept", s);
      auto protocol = lsi->second;
      sockaddr_in addr;
      sock_t as = Socket::accept(s, addr);
      if (as <= 0)
      {
        logger(TCPSERVER, LogLevel::ERROR).log("accept::error", s, as, errno, ::strerror(errno));
        return;
      }
      auto conn = std::make_shared<Connection>(as, protocol);
      _connections.emplace(as, conn);
      _loop->add(as, this);
      DataEvent data{.buffer = DataEvent::Buffer(), .connect = true};
      _dispatcher->postForConnection(
          conn, [conn, data = std::move(data)]() mutable { conn->getProtocol()->onReceive(conn, std::move(data)); });
      return;
    }

    auto it = _connections.find(s);
    if (it != _connections.end())
    {
      auto &conn = it->second;

      DataEvent data{DataEvent::Buffer(4096)};
      auto len = Socket::recv(s, data.buffer.data(), data.buffer.size(), 0);
      auto err = errno;

      logger(TCPSERVER, LogLevel::DEBUG).log("recv", s, len);

      if (len > 0)
      {
        data.buffer.resize(static_cast<size_t>(len)); // set actual buffer size
        _dispatcher->postForConnection(
            conn, [conn, data = std::move(data)]() mutable { conn->getProtocol()->onReceive(conn, std::move(data)); });
      }
      else if (len == 0)
      {
        conn->setClosed(true);
        logger(TCPSERVER, LogLevel::DEBUG).log("recv::disconnect", s);
        if (conn->hasGenerator())
        {
          logger(TCPSERVER, LogLevel::DEBUG).log("disconnect::gen::stop", s);
          conn->clearGenerator();
        }
        send(conn, DataEvent{.buffer = DataEvent::Buffer(), .close = true}); // trigger close on next drain
        // close(s);
      }
      else if (err == EAGAIN || err == EWOULDBLOCK)
      {
        // not ready, skip
      }
      else
      {
        logger(TCPSERVER, LogLevel::ERROR).log("recv::error", s, len, err, ::strerror(err));
        close(s);
      }
      return;
    }

    logger(TCPSERVER, LogLevel::WARN).log("unknown", s);
  }

  virtual void handleWriting(sock_t s) override
  {
    logger(TCPSERVER, LogLevel::DEBUG).log(s);

    auto it = _connections.find(s);
    if (it != _connections.end())
    {

      auto conn = it->second;
      DrainResult result =
          _dispatcher->drainSendQueue(conn, [this](ConnectionPtr conn) { return drainSendQueue(conn); });

      logger(TCPSERVER, LogLevel::DEBUG).log(s, result);
      switch (result)
      {
      case DrainResult::Done:
        _loop->add(s, this, false); // all sent, stop watching writes
        break;
      case DrainResult::Close:
        close(s);
        break;
      case DrainResult::Partial:
        break;
      }

      if (result != DrainResult::Close && conn->hasGenerator())
      {
        logger(TCPSERVER, LogLevel::DEBUG).log("gen:cont", s);
        _dispatcher->postRecv([this, conn] {
          if (!conn->isClosed() && conn->hasGenerator())
          {
            send(conn, conn->runGenerator());
          }
        });
      }
      return;
    }

    logger(TCPSERVER, LogLevel::WARN).log("unknown", s);
  }

  std::vector<ConnectionPtr> getProtocolConnections(Protocol *protocol) const
  {
    // TODO: lock for other threads access
    std::vector<ConnectionPtr> connections;
    for (const auto &pair : _connections)
    {
      if (pair.second->getProtocol() == protocol && !pair.second->isClosed())
      {
        connections.push_back(pair.second);
      }
    }
    return connections;
  }

  DrainResult drainSendQueue(ConnectionPtr conn)
  {
    auto &queue = conn->sendQueue();
    logger(TCPSERVER, LogLevel::DEBUG).log(conn->getId(), queue.size());
    if (queue.empty())
    {
      return DrainResult::Done;
    }
    while (!queue.empty())
    {
      auto &data = queue.front();

      // connection is closed by remote
      if (conn->isClosed())
      {
        // do not need to prune queue as connection destuctor will do it
        return DrainResult::Close;
      }

      // drain if needed
      if (data.sent < data.buffer.size())
      {
        if (!drainSentData(conn, data))
        {
          // not all chunk data were sent, we need to reply drain, do not pop yet
          return DrainResult::Partial; // EAGAIN, wait for next handleWriting
        }
      }

      if (data.close)
      {
        return DrainResult::Close; // chunk with close flag
      }

      queue.pop();
    }

    return DrainResult::Done;
  }

  bool drainSentData(ConnectionPtr conn, DataEvent &data)
  {
    if (data.buffer.empty())
    {
      return true;
    }

    do
    {
      auto len = Socket::send(conn->getId(), data.buffer.data() + data.sent, data.buffer.size() - data.sent, 0);
      auto err = errno;
      logger(TCPSERVER, LogLevel::DEBUG).log(conn->getId(), len, data.close);
      if (len < 0)
      {
        if (err == EAGAIN || err == EWOULDBLOCK)
        {
          // unable to drain connection buffer, wait for next writable event
          return false;
        }
        logger(TCPSERVER, LogLevel::ERROR).log(conn->getId(), len, err, ::strerror(err));
        data.close = true;              // mark for close
        data.sent = data.buffer.size(); // mark as "done" so close triggers
        return true;
      }
      else
      {
        data.sent += static_cast<size_t>(len);
      }
    } while (data.sent < data.buffer.size());
    return true;
  }

  void send(ConnectionPtr conn, MoveOnlyFunction<DataEvent(void)> generator)
  {
    conn->setGenerator(std::move(generator));
    send(conn, conn->runGenerator());
  }

  void send(ConnectionPtr conn, DataEvent data)
  {
    if (conn->isClosed())
    {
      return;
    }
    _dispatcher->send(conn, std::move(data));
    _loop->notify(conn->getId()); // make sure we're watching writable events for this connection
  }

private:
  void close(sock_t s)
  {
    logger(TCPSERVER, LogLevel::DEBUG).log(s);
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
};

} // namespace Netpp
