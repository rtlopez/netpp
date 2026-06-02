#pragma once

#include <memory>
#include <mutex>
#include <queue>
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
      auto protocol = _protocols.at(s);
      auto conn = it->second;
      //_dispatcher->postRecv([protocol, conn] {
      protocol->onError(conn);
      //});
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
        if (_connections.contains(ws))
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
      auto conn = std::make_shared<Connection>(as);
      _protocols.emplace(as, protocol);
      _connections.emplace(as, conn);
      _loop->add(as, this);
      _dispatcher->onConnect(as);
      //_dispatcher->postRecv([protocol, conn] {
      protocol->onConnect(conn);
      //});
    }
    else
    {
      auto it = _connections.find(s);
      if (it != _connections.end())
      {
        auto &conn = it->second;
        auto protocol = _protocols.at(s);

        DataEvent data{conn, DataEvent::Buffer(4096)};
        auto len = Socket::recv(s, data.buffer.data(), data.buffer.size(), 0);
        auto err = errno;

        logger(TCPSERVER, LogLevel::DEBUG).log("recv", s, len);

        if (len > 0)
        {
          data.buffer.resize(static_cast<size_t>(len)); // set actual buffer size
          _dispatcher->postRecv([protocol, data = std::move(data)]() mutable { protocol->onReceive(std::move(data)); });
        }
        else if (len == 0)
        {
          logger(TCPSERVER, LogLevel::DEBUG).log("recv::disconnect", s);
          {
            std::scoped_lock lock(_generatorsMutex);
            if (_generators.contains(s))
            {
              logger(TCPSERVER, LogLevel::DEBUG).log("disconnect::gen::stop", s);
              _generators.erase(s);
            }
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
    DrainResult result;
    {
      auto sendLock = _dispatcher->lockSend(s);
      result = drainSent(s);
    }
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
    {
      std::scoped_lock lock(_generatorsMutex);
      if (_generators.contains(s))
      {
        if (result != DrainResult::Close)
        {
          logger(TCPSERVER, LogLevel::DEBUG).log("gen:cont", s);
          _dispatcher->postRecv([this, s] {
            DataEvent data;
            {
              std::scoped_lock lock(_generatorsMutex);
              auto it = _generators.find(s);
              if (it == _generators.end())
              {
                return;
              }
              data = it->second();
            }
            send(std::move(data));
          });
        }
        else
        {
          logger(TCPSERVER, LogLevel::DEBUG).log("gen::stop", s);
          _generators.erase(s);
        }
      }
    }
  }

  DrainResult drainSent(sock_t s)
  {
    auto &queue = _dispatcher->getSendQueue(s);
    logger(TCPSERVER, LogLevel::DEBUG).log(s, queue.size());
    if (queue.empty())
    {
      return DrainResult::Done;
    }
    while (!queue.empty())
    {
      auto &data = queue.front();
      bool drained = data.sent >= data.buffer.size();

      // re-entry check: if already marked for close and fully sent, close connection
      if (data.close && drained)
      {
        queue.pop();
        return DrainResult::Close;
      }

      // drain if needed
      if (!drained)
      {
        if (!drainSent(s, data))
        {
          return DrainResult::Partial; // EAGAIN, wait for next handleWriting
        }
      }

      // if it is closing batch, wait till fully sent before popping
      if (data.close)
      {
        return DrainResult::Partial; // will keep monitoring
      }

      queue.pop();
    }
    return DrainResult::Done;
  }

  bool drainSent(sock_t s, DataEvent &data)
  {
    if (data.buffer.empty())
    {
      return true;
    }

    do
    {
      auto len = Socket::send(s, data.buffer.data() + data.sent, data.buffer.size() - data.sent, 0);
      auto err = errno;
      logger(TCPSERVER, LogLevel::DEBUG).log(s, len, data.close);
      if (len < 0)
      {
        if (err == EAGAIN || err == EWOULDBLOCK)
        {
          // unable to drain connection buffer, wait for next writable event
          return false;
        }
        else
        {
          logger(TCPSERVER, LogLevel::ERROR).log(s, len, err, ::strerror(err));
          data.close = true;              // mark for close
          data.sent = data.buffer.size(); // mark as "done" so close triggers
          return true;
        }
      }
      else
      {
        data.sent += static_cast<size_t>(len);
      }
    } while (data.sent < data.buffer.size());
    return true;
  }

  void send(DataEvent data)
  {
    auto s = data.conn->getId(); // note std::move later
    _dispatcher->send(std::move(data));
    if (_notifyFd < 0)
    {
      _loop->add(s, this, true); // single-thread: enable write watching directly
    }
    // in threaded mode, ThreadPoolDispatcher::send() notifies via eventfd
  }

  void send(MoveOnlyFunction<DataEvent(void)> generator)
  {
    auto data = generator();
    auto s = data.conn->getId(); // note std::move later
    {
      std::scoped_lock lock(_generatorsMutex);
      _generators.emplace(s, std::move(generator));
    }
    send(std::move(data));
  }

private:
  void close(sock_t s)
  {
    logger(TCPSERVER, LogLevel::DEBUG).log(s);
    auto it = _connections.find(s);
    bool known = it != _connections.end();
    if (known)
    {
      auto protocol = _protocols.at(s);
      auto conn = it->second;
      //_dispatcher->postRecv([protocol, conn] {
      protocol->onDisconnect(conn);
      //});
      _protocols.erase(s);
    }
    _dispatcher->onDisconnect(s);
    _loop->del(s);
    if (known)
    {
      _connections.erase(it);
    }
    // _connections.emplace(as, conn);
    // _protocols.emplace(as, protocol);
    // _loop->add(as, this);
    // _dispatcher->onConnect(as);
    // _protocol->onConnect(conn);
  }

  EventLoop *_loop;
  Dispatcher *_dispatcher;
  sock_t _notifyFd;
  std::unordered_map<sock_t, Protocol *> _listeners;
  std::unordered_map<sock_t, Protocol *> _protocols;
  std::unordered_map<sock_t, ConnectionPtr> _connections;
  std::unordered_map<sock_t, MoveOnlyFunction<DataEvent(void)>> _generators;
  std::mutex _generatorsMutex;
};

} // namespace Netpp
