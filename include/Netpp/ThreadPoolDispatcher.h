#pragma once

#include <condition_variable>
#include <mutex>
#include <queue>
#include <thread>
#include <vector>

#include "Dispatcher.h"
#include "MoveOnlyFunction.h"
#include "Netpp/Logger/Logger.h"

namespace Netpp
{

using Netpp::Logger::logger;
using Netpp::Logger::LogLevel;
static const char *DISPATCH = "dispatch";

class ThreadPoolDispatcher : public Dispatcher
{
public:
  ThreadPoolDispatcher(EventLoop *loop, size_t numThreads = 8) : Dispatcher(loop), _workers(numThreads), _stop(false)
  {
    logger(DISPATCH, LogLevel::DEBUG).log(numThreads);
    for (size_t i = 0; i < numThreads; i++)
    {
      _workers.emplace_back([this] { workerLoop(); });
    }
  }

  virtual ~ThreadPoolDispatcher()
  {
    logger(DISPATCH, LogLevel::DEBUG).log("");
    {
      std::scoped_lock lock(_taskMutex);
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
    conn->sendQueue().push(std::move(data));
  }

  DrainResult drainSendQueue(ConnectionPtr conn, std::function<DrainResult(ConnectionPtr)> drainFunc) override
  {
    std::scoped_lock sendLock(conn->sendMutex());
    return drainFunc(conn);
  }

  // --- Thread pool interface ---

  void postRecv(MoveOnlyFunction<void()> task) override
  {
    logger(DISPATCH, LogLevel::TRACE).log("");
    {
      std::scoped_lock lock(_taskMutex);
      _taskQueue.push(std::move(task));
    }
    _taskCv.notify_one();
  }

  void postForConnection(ConnectionPtr conn, MoveOnlyFunction<void()> task) override
  {
    logger(DISPATCH, LogLevel::TRACE).log(conn->getId());
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
      postRecv([this, weak] { drainConnectionTasks(weak); });
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
        logger(DISPATCH, LogLevel::DEBUG).log("connection expired, dropping tasks");
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
      logger(DISPATCH, LogLevel::TRACE).log("");
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
