#pragma once

#include <memory>
#include <queue>
#include <unordered_map>

#include "Netpp/Connection.h"
#include "Netpp/DataEvent.h"
#include "Netpp/Dispatcher.h"
#include "Netpp/EventLoop.h"
#include "Netpp/EventLoopHandler.h"
#include "Netpp/NetppDebug.h"
#include "Netpp/Protocol.h"
#include "Netpp/Socket.h"

namespace Netpp
{

class TcpServer : public EventLoopHandler
{
public:
  TcpServer(EventLoop *loop, Dispatcher *dispatcher) : _loop(loop), _dispatcher(dispatcher)
  {
  }

  void listen(const char *addr, uint16_t port, Protocol *protocol)
  {
    debug("TcpServer::listen", addr, port);
    sock_t s = Socket::create(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);
    Socket::bind(s, addr, port);
    Socket::listen(s, 128);
    _listeners.emplace(s, protocol);
    _loop->add(s, this);
  }

  virtual ~TcpServer()
  {
    debug("~TcpServer");
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
      protocol->onError(it->second);
    }
    close(s);
  }

  virtual void handleReading(sock_t s) override
  {
    auto lsi = _listeners.find(s);
    if (lsi != _listeners.end())
    {
      debug("TcpServer::accept", s);
      auto protocol = lsi->second;
      sockaddr_in addr;
      sock_t as = Socket::accept(s, addr);
      if (as <= 0)
      {
        debug("TcpServer::accept::error", s, as, errno, ::strerror(errno));
        return;
      }
      auto conn = std::make_shared<Connection>(as);
      _protocols.emplace(as, protocol);
      _connections.emplace(as, conn);
      _dispatcher->onConnect(as);
      protocol->onConnect(conn);
      _loop->add(as, this);
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

        debug("TcpServer::recv", s, len);

        if (len > 0)
        {
          data.buffer.resize(static_cast<size_t>(len)); // set actual buffer size
          post(std::move(data), protocol);
        }
        else if (len == 0)
        {
          debug("TcpServer::recv::disconnect", s);
          close(s);
        }
        else if (err == EAGAIN || err == EWOULDBLOCK)
        {
          // skip
        }
        else
        {
          debug("TcpServer::recv::error", s, len, err, ::strerror(err));
          close(s);
        }
      }
      else
      {
        debug("TcpServer::recv::unknown", s);
        close(s);
      }
    }

    drainRecv();
  }

  enum DrainResult
  {
    Done,
    Partial,
    Close
  };

  virtual void handleWriting(sock_t s) override
  {
    debug("TcpServer::handleWriting", s);
    auto result = drainSent(s);
    switch (result)
    {
    case DrainResult::Done:
      debug("TcpServer::handleWriting::done", s);
      _loop->add(s, this, false); // all sent, stop watching writes
      break;
    case DrainResult::Close:
      debug("TcpServer::handleWriting::close", s);
      close(s);
      break;
    case DrainResult::Partial:
      debug("TcpServer::handleWriting::partial", s);
      break;
    }
  }

  void drainRecv()
  {
    debug("TcpServer::drainRecv", _recvQueue.size());
    while (!_recvQueue.empty())
    {
      auto &item = _recvQueue.front();
      item.target->onReceive(std::move(item.data));
      _recvQueue.pop();
    }
  }

  DrainResult drainSent(sock_t s)
  {
    auto &queue = _dispatcher->getSendQueue(s);
    debug("TcpServer::drainSent", s, queue.size());
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
        _dispatcher->onSendDone(s);
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
    _dispatcher->onSendDone(s);
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
      debug("TcpServer::flush", s, len, data.close);
      if (len < 0)
      {
        if (err == EAGAIN || err == EWOULDBLOCK)
        {
          // unable to drain connection buffer, wait for next writable event
          return false;
        }
        else
        {
          debug("TcpServer::flush::error", s, len, err, ::strerror(err));
          data.close = true; // mark for close
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
    auto id = data.conn->getId(); // note std::move later
    _dispatcher->send(std::move(data));
    _loop->add(id, this, true); // enable write watching
  }

private:
  void post(DataEvent data, Protocol *target)
  {
    _recvQueue.push({std::move(data), target});
  }

  void close(sock_t s)
  {
    debug("TcpServer::close", s);
    _loop->del(s);
    auto it = _connections.find(s);
    bool known = it != _connections.end();
    if (known)
    {
      auto protocol = _protocols.at(s);
      protocol->onDisconnect(it->second);
      _protocols.erase(s);
    }
    _dispatcher->onDisconnect(s);
    if (known)
    {
      _connections.erase(it);
    }
    // _connections.emplace(as, conn);
    // _protocols.emplace(as, protocol);
    // _dispatcher->onConnect(as);
    // _protocol->onConnect(conn);
    // _loop->add(as, this);
  }

  EventLoop *_loop;
  Dispatcher *_dispatcher;
  std::unordered_map<sock_t, Protocol *> _listeners;
  std::unordered_map<sock_t, Protocol *> _protocols;
  std::unordered_map<sock_t, ConnectionPtr> _connections;
  struct RecvItem
  {
    DataEvent data;
    Protocol *target;
  };

  std::queue<RecvItem> _recvQueue;
};

} // namespace Netpp
