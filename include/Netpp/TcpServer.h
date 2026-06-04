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
  TcpServer(EventLoop *loop, Dispatcher *dispatcher) : _loop(loop), _dispatcher(dispatcher), _notifyFd(-1)
  {
    _notifyFd = _dispatcher->getNotifyFd();
    if (_notifyFd >= 0)
    {
      _loop->add(_notifyFd, this);
    }
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
    logger(TCPSERVER, LogLevel::DEBUG).log(_notifyFd, _listeners.size());
    if (_notifyFd >= 0)
    {
      _loop->del(_notifyFd);
    }
    for (auto &[s, protocol] : _listeners)
    {
      _loop->del(s);
      Socket::close(s);
    }
  }

  virtual void handleError(sock_t s) override
  {
    auto it = _connections.find(s);
    if (it != _connections.end())
    {
      auto conn = it->second;
      _dispatcher->postForConnection(conn, [conn] { conn->getProtocol()->onError(conn); });
    }
    close(s);
  }

  virtual void handleReading(sock_t s) override
  {
    if (s == _notifyFd)
    {
      uint64_t val;
      ::read(_notifyFd, &val, sizeof(val));
      auto sockets = _dispatcher->drainPendingWrites();
      for (auto ws : sockets)
      {
        if (_connections.contains(ws)) // signity check??
        {
          _loop->add(ws, this, true);
        }
      }
      return;
    }

    auto lsi = _listeners.find(s);
    if (lsi != _listeners.end())
    {
      logger(TCPSERVER, LogLevel::DEBUG).log("accept", s);
      auto protocol = lsi->second;
      sockaddr_in addr;
      sock_t as = Socket::accept(s, addr);
      if (as <= 0)
      {
        logger(TCPSERVER, LogLevel::ERROR).log("accept error", s, as, errno, ::strerror(errno));
        return;
      }
      auto conn = std::make_shared<Connection>(as, protocol);
      _connections.emplace(as, conn);
      _loop->add(as, this);
      _dispatcher->postForConnection(conn, [conn] { conn->getProtocol()->onConnect(conn); });
    }
    else
    {
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
          _dispatcher->postForConnection(conn, [conn, data = std::move(data)]() mutable {
            conn->getProtocol()->onReceive(conn, std::move(data));
          });
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
          close(s);
        }
        else if (err == EAGAIN || err == EWOULDBLOCK)
        {
          // skip
        }
        else
        {
          logger(TCPSERVER, LogLevel::ERROR).log("recv::error", s, len, err, ::strerror(err));
          close(s);
        }
      }
      else
      {
        logger(TCPSERVER, LogLevel::DEBUG).log("recv::unknown", s);
        close(s);
      }
    }
  }

  enum DrainResult
  {
    Done,
    Partial,
    Close
  };

  virtual void handleWriting(sock_t s) override
  {
    logger(TCPSERVER, LogLevel::DEBUG).log(s);

    auto it = _connections.find(s);
    if (it == _connections.end())
    {
      logger(TCPSERVER, LogLevel::WARN).log("unknown", s);
      return;
    }

    auto conn = it->second;
    DrainResult result = drainSent(conn);

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
          auto data = conn->runGenerator();
          send(conn, std::move(data));
        }
      });
    }
  }

  DrainResult drainSent(ConnectionPtr conn)
  {
    std::scoped_lock sendLock(conn->sendMutex());
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
    auto data = generator();
    conn->setGenerator(std::move(generator));
    send(conn, std::move(data));
  }

  void send(ConnectionPtr conn, DataEvent data)
  {
    _dispatcher->send(conn, std::move(data));
    if (_notifyFd < 0)
    {
      // single-thread: enable write watching directly
      _loop->add(conn->getId(), this, true);
    }
    // in threaded mode, ThreadPoolDispatcher::send() notifies via eventfd
  }

private:
  void close(sock_t s)
  {
    logger(TCPSERVER, LogLevel::DEBUG).log(s);
    auto it = _connections.find(s);
    if (it == _connections.end())
    {
      return; // already closed
    }
    _loop->del(s); // remove from epoll before closing the fd
    auto conn = it->second;
    _connections.erase(it); // Connection destructor closes the fd
    _dispatcher->postForConnection(conn, [conn] { conn->getProtocol()->onDisconnect(conn); });
  }

  EventLoop *_loop;
  Dispatcher *_dispatcher;
  sock_t _notifyFd;
  std::unordered_map<sock_t, Protocol *> _listeners;
  std::unordered_map<sock_t, ConnectionPtr> _connections;
};

} // namespace Netpp
