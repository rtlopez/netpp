#pragma once

#include <condition_variable>
#include <mutex>
#include <queue>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <sys/eventfd.h>
#include <unistd.h>

#include "Dispatcher.h"
#include "MoveOnlyFunction.h"
#include "NetppDebug.h"

namespace Netpp
{

class ThreadPoolDispatcher : public Dispatcher
{
public:
  ThreadPoolDispatcher(size_t numThreads = 8) : _stop(false)
  {
    _eventFd = ::eventfd(0, EFD_NONBLOCK);
    if (_eventFd < 0)
    {
      throw std::runtime_error("eventfd() failed");
    }

    debug("ThreadPoolDispatcher", numThreads, _eventFd);

    for (size_t i = 0; i < numThreads; i++)
    {
      _workers.emplace_back([this] { workerLoop(); });
    }
  }

  virtual ~ThreadPoolDispatcher()
  {
    {
      std::lock_guard<std::mutex> lock(_taskMutex);
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

    if (_eventFd >= 0)
    {
      ::close(_eventFd);
    }
  }

  // --- Dispatcher interface ---

  void send(DataEvent data) override
  {
    auto s = data.conn->getId();
    {
      std::lock_guard<std::mutex> lock(_sendMutex);
      auto it = _sendQueues.find(s);
      if (it == _sendQueues.end())
      {
        return; // connection already closed
      }
      it->second.push(std::move(data));
    }
    notifyWrite(s);
  }

  void onConnect(sock_t s) override
  {
    debug("ThreadPoolDispatcher::onConnect", s);
    std::lock_guard<std::mutex> lock(_sendMutex);
    _sendQueues.emplace(s, std::queue<DataEvent>{});
  }

  void onDisconnect(sock_t s) override
  {
    debug("ThreadPoolDispatcher::onDisconnect", s);
    std::lock_guard<std::mutex> lock(_sendMutex);
    _sendQueues.erase(s);
  }

  std::queue<DataEvent> &getSendQueue(sock_t s) override
  {
    return _sendQueues.at(s);
  }

  std::unique_lock<std::mutex> lockSend(sock_t) override
  {
    return std::unique_lock<std::mutex>(_sendMutex);
  }

  // --- Thread pool interface ---

  sock_t getNotifyFd() const override
  {
    return _eventFd;
  }

  std::vector<sock_t> drainPendingWrites() override
  {
    std::lock_guard<std::mutex> lock(_notifyMutex);
    std::vector<sock_t> result(_pendingWrites.begin(), _pendingWrites.end());
    _pendingWrites.clear();
    return result;
  }

  void postRecv(MoveOnlyFunction<void()> task) override
  {
    {
      std::lock_guard<std::mutex> lock(_taskMutex);
      _recvQueue.push(std::move(task));
    }
    _taskCv.notify_one();
  }

private:
  void workerLoop()
  {
    while (true)
    {
      MoveOnlyFunction<void()> task;
      {
        std::unique_lock<std::mutex> lock(_taskMutex);
        _taskCv.wait(lock, [this] { return _stop || !_recvQueue.empty(); });
        if (_stop && _recvQueue.empty())
        {
          return;
        }
        task = std::move(_recvQueue.front());
        _recvQueue.pop();
      }
      task();
    }
  }

  void notifyWrite(sock_t s)
  {
    {
      std::lock_guard<std::mutex> lock(_notifyMutex);
      _pendingWrites.insert(s);
    }
    uint64_t val = 1;
    ::write(_eventFd, &val, sizeof(val));
  }

  // Thread pool
  std::vector<std::thread> _workers;
  bool _stop;

  // Recv/task queue (main thread produces, workers consume)
  std::queue<MoveOnlyFunction<void()>> _recvQueue;
  std::mutex _taskMutex;
  std::condition_variable _taskCv;

  // Send queues (workers produce, main thread consumes)
  std::unordered_map<sock_t, std::queue<DataEvent>> _sendQueues;
  std::mutex _sendMutex;

  // Notification
  sock_t _eventFd;
  std::unordered_set<sock_t> _pendingWrites;
  std::mutex _notifyMutex;
};

} // namespace Netpp
