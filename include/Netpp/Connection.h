#pragma once

#include <atomic>
#include <memory>
#include <mutex>
#include <queue>
#include <string>

#include "Netpp/DataEvent.h"
#include "Netpp/Logger/Logger.h"
#include "Netpp/MoveOnlyFunction.h"
#include "Socket.h"

namespace Netpp
{

class Protocol;

using Netpp::Logger::logger;
using Netpp::Logger::LogLevel;
static const char *CONNECTION = "connection";

class Connection
{
public:
  Connection(sock_t s, Protocol *protocol = nullptr) : _s(s), _protocol(protocol)
  {
    logger(CONNECTION, LogLevel::DEBUG).log(_s);
  }

  virtual ~Connection()
  {
    if (_context)
    {
      _context.reset();
    }
    logger(CONNECTION, LogLevel::DEBUG).log(_s);
    if (_s >= 0)
    {
      Socket::close(_s);
      _s = -1;
    }
  }

  std::string getPeerName() const
  {
    return Socket::getpeername(_s);
  }

  int getId() const
  {
    return static_cast<int>(_s);
  }

  Protocol *getProtocol() const
  {
    return _protocol;
  }

  // Protocol-specific context: type-erased, owned by the connection and
  // released automatically when the connection is destroyed.
  void setContext(std::shared_ptr<void> ctx)
  {
    _context = std::move(ctx);
  }

  template <typename T>
  std::shared_ptr<T> getContext() const
  {
    return std::static_pointer_cast<T>(_context);
  }

  // Generator: produces DataEvents for streaming sends
  void setGenerator(MoveOnlyFunction<DataEvent(void)> gen)
  {
    _generator = std::move(gen);
  }

  bool hasGenerator()
  {
    return static_cast<bool>(_generator);
  }

  DataEvent runGenerator()
  {
    return _generator();
  }

  void clearGenerator()
  {
    _generator = {};
  }

  std::mutex &generatorMutex()
  {
    return _generatorMutex;
  }

  bool operator==(const Connection &other) const
  {
    return _s == other._s;
  }

  bool operator!=(const Connection &other) const
  {
    return !(*this == other);
  }

  // Send queue: per-connection outgoing data
  std::mutex &sendMutex()
  {
    return _sendMutex;
  }

  std::deque<DataEvent> &sendQueue()
  {
    return _sendQueue;
  }

  // Strand: per-connection task serialization
  std::mutex &strandMutex()
  {
    return _strandMutex;
  }

  std::queue<MoveOnlyFunction<void()>> &taskQueue()
  {
    return _taskQueue;
  }

  bool isProcessing() const
  {
    return _processing.load(std::memory_order_acquire);
  }

  void setProcessing(bool v)
  {
    _processing.store(v, std::memory_order_release);
  }

  void setClosed(bool v)
  {
    _closed.store(v, std::memory_order_release);
  }

  bool isClosed() const
  {
    return _closed.load(std::memory_order_acquire);
  }

private:
  sock_t _s;
  Protocol *_protocol;

  // Protocol-specific context (type-erased)
  std::shared_ptr<void> _context;

  // Send queue state
  std::deque<DataEvent> _sendQueue;
  std::mutex _sendMutex;

  // Generator state
  MoveOnlyFunction<DataEvent(void)> _generator;
  std::mutex _generatorMutex;

  // Strand state (used by ThreadPoolDispatcher)
  std::queue<MoveOnlyFunction<void()>> _taskQueue;
  std::mutex _strandMutex;
  std::atomic<bool> _processing = false;

  // remote closed connection
  std::atomic<bool> _closed = false;
};

static_assert(std::atomic<bool>::is_always_lock_free, "std::atomic<bool> must be lock-free");

using ConnectionPtr = std::shared_ptr<Connection>;
using ConnectionWeakPtr = std::weak_ptr<Connection>;

} // namespace Netpp
