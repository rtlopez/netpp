#pragma once

#include <condition_variable>
#include <memory>
#include <mutex>
#include <queue>
#include <thread>
#include <vector>

#include "Dispatcher.h"
#include "Logger/Logger.h"

namespace Netpp
{

using Netpp::Logger::logger;
using Netpp::Logger::LogLevel;
static const char *TDISPATCH = "dispatch";

// schedule received data processing to thread pool and drain send queue in main thread
class ThreadPoolDispatcher : public Dispatcher
{
public:
  ThreadPoolDispatcher(EventLoop *loop, size_t numThreads = 8) : Dispatcher(loop), _stop(false)
  {
    logger(TDISPATCH, LogLevel::DEBUG, numThreads);
    _workers.reserve(numThreads);
    for (size_t i = 0; i < numThreads; i++)
    {
      _workers.emplace_back([this] { workerLoop(); });
    }
  }

  virtual ~ThreadPoolDispatcher()
  {
    stop();
  }

  void stop() override
  {
    logger(TDISPATCH, LogLevel::DEBUG, "");
    {
      std::scoped_lock lock(_taskMutex);
      if (_stop)
      {
        return; // already stopped
      }
      _stop = true;
    }
    _taskCv.notify_all();

    for (auto &w : _workers)
    {
      if (w.joinable())
      {
        w.join();
      }
    }
  }

  // --- Dispatcher interface ---

  void send(ConnectionPtr conn, DataEvent data) override
  {
    std::scoped_lock lock(conn->sendMutex());
    conn->sendQueue().push_back(std::move(data));
    _loop->mod(conn->getId(), true); // notify loop that it has to drain send queue
  }

  void send(ConnectionPtr conn, MoveOnlyFunction<DataEvent(void)> generator) override
  {
    DataEvent data;
    {
      std::scoped_lock generatorLock(conn->generatorMutex());
      conn->setGenerator(std::move(generator));
      data = conn->runGenerator();
    }
    send(conn, std::move(data));
  }

  void runGenerator(ConnectionPtr conn) override
  {
    ConnectionWeakPtr weak{conn};
    post([this, weak] {
      if (auto conn = weak.lock())
      {
        DataEvent data;
        {
          std::scoped_lock generatorLock(conn->generatorMutex());
          if (!conn->hasGenerator())
          {
            return;
          }
          logger(TDISPATCH, LogLevel::DEBUG, conn->getId(), "gen:cont");
          data = conn->runGenerator();
        }
        send(conn, std::move(data));
      }
    });
  }

  DrainResult drain(ConnectionPtr conn, std::function<bool(ConnectionPtr, DataEvent &)> sendFunc) override
  {
    auto &queue = conn->sendQueue();
    {
      std::scoped_lock sendLock(conn->sendMutex());
      logger(TDISPATCH, LogLevel::DEBUG, conn->getId(), queue.size());
    }
    while (true)
    {
      DataEvent data;
      {
        std::scoped_lock sendLock(conn->sendMutex());
        if (queue.empty())
        {
          _loop->mod(conn->getId(), false); // not more data to drain, notify loop to stop waiting for writable event
          break;
        }
        data = std::move(queue.front());
        queue.pop_front();
      }

      // drain if needed
      if (data.sent < data.buffer.size())
      {
        if (!sendFunc(conn, data))
        {
          std::scoped_lock sendLock(conn->sendMutex());
          // not all chunk data were sent, we need to reply drain, push back to queue front
          queue.push_front(std::move(data));

          return DrainResult::Partial; // EAGAIN, wait for next handleWriting
        }
      }

      if (data.close)
      {
        return DrainResult::Close; // chunk with close flag
      }
    }
    return DrainResult::Done;
  }

  // --- Thread pool interface ---

  void post(MoveOnlyFunction<void()> task) override
  {
    logger(TDISPATCH, LogLevel::TRACE, "");
    {
      std::scoped_lock lock(_taskMutex);
      _taskQueue.push(std::move(task));
    }
    _taskCv.notify_one();
  }

  void post(ConnectionPtr conn, MoveOnlyFunction<void()> task) override
  {
    logger(TDISPATCH, LogLevel::TRACE, conn->getId());
    bool shouldSchedule = false;
    {
      std::scoped_lock lock(conn->strandMutex());
      conn->taskQueue().push(std::move(task));
      if (!conn->isProcessing())
      {
        conn->setProcessing(true);
        shouldSchedule = true;
      }
    }
    if (shouldSchedule)
    {
      ConnectionWeakPtr weak{conn};
      post([this, weak] { drainConnectionTasks(weak); });
    }
  }

private:
  void drainConnectionTasks(ConnectionWeakPtr weak)
  {
    while (true)
    {
      auto conn = weak.lock();
      if (!conn)
      {
        logger(TDISPATCH, LogLevel::DEBUG, "connection expired, dropping tasks");
        return;
      }
      MoveOnlyFunction<void()> task;
      {
        std::scoped_lock lock(conn->strandMutex());
        auto &queue = conn->taskQueue();
        if (queue.empty())
        {
          conn->setProcessing(false);
          return;
        }
        task = std::move(queue.front());
        queue.pop();
      }
      task();
    }
  }

  void workerLoop()
  {
    while (true)
    {
      MoveOnlyFunction<void()> task;
      {
        std::unique_lock<std::mutex> lock(_taskMutex);
        _taskCv.wait(lock, [this] { return _stop || !_taskQueue.empty(); });
        if (_stop && _taskQueue.empty())
        {
          return;
        }
        task = std::move(_taskQueue.front());
        _taskQueue.pop();
      }
      logger(TDISPATCH, LogLevel::TRACE, "");
      task();
    }
  }

  // Thread pool
  std::vector<std::thread> _workers;
  bool _stop;

  // Recv/task queue (main thread produces, workers consume)
  std::queue<MoveOnlyFunction<void()>> _taskQueue;
  std::mutex _taskMutex;
  std::condition_variable _taskCv;
};

} // namespace Netpp
