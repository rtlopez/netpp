#pragma once

#include "Netpp/Dispatcher.h"
#include "Netpp/Logger/Logger.h"

namespace Netpp::Core
{
using Logger::logger;
using Logger::LogLevel;

// single-threaded, immediate execution, no thread pool, for testing and simple use cases
class SingleThreadDispatcher : public Dispatcher
{
public:
  static constexpr const char *DISPATCH = "dispatch";

  SingleThreadDispatcher(EventLoop *loop) : Dispatcher(loop)
  {
  }

  void send(ConnectionPtr conn, DataEvent data) override
  {
    conn->sendQueue().push_back(std::move(data));
    _loop->mod(conn->getId(), true); // notify loop that it has to drain send queue
  }

  void send(ConnectionPtr conn, MoveOnlyFunction<DataEvent(void)> generator) override
  {
    conn->setGenerator(std::move(generator));
    send(conn, conn->runGenerator());
  }

  void runGenerator(ConnectionPtr conn) override
  {
    if (conn->hasGenerator())
    {
      logger(DISPATCH, LogLevel::DEBUG, conn->getId(), "gen:cont");
      send(conn, conn->runGenerator());
    }
  }

  void post(MoveOnlyFunction<void()> task) override
  {
    logger(DISPATCH, LogLevel::TRACE, "fn");
    task();
  }

  void post(ConnectionPtr conn, MoveOnlyFunction<void()> task) override
  {
    logger(DISPATCH, LogLevel::TRACE, conn->getId(), "con");
    task();
  }

  DrainResult drain(ConnectionPtr conn, std::function<bool(ConnectionPtr, DataEvent &)> sendFunc) override
  {
    auto &queue = conn->sendQueue();
    logger(DISPATCH, LogLevel::DEBUG, conn->getId(), queue.size());
    while (!queue.empty())
    {
      auto &data = queue.front();

      // drain if needed
      if (data.sent < data.buffer.size())
      {
        if (!sendFunc(conn, data))
        {
          // not all chunk data were sent, we need to reply drain, push back to queue front
          return DrainResult::Partial; // EAGAIN, wait for next handleWriting
        }
      }

      if (data.close)
      {
        // no need to pop as connection destructor will do it
        return DrainResult::Close; // chunk with close flag
      }

      queue.pop_front();
    }

    _loop->mod(conn->getId(), false);
    return DrainResult::Done;
  }
};

} // namespace Netpp::Core
