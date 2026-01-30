#pragma once
#include <vector>
#include <thread>
#include <queue>
#include <functional>
#include <mutex>
#include <condition_variable>
#include <atomic>

class ThreadPool
{
public:
    explicit ThreadPool(std::size_t threadCount);
    ~ThreadPool();

    // Enqueues a task for execution; returns immediately.
    void post(std::function<void()> task);
    // Blocks until all queued tasks are finished.
    void wait();
private:
    void workerLoop();

    std::vector<std::thread> workers_;
    std::queue<std::function<void()>> tasks_;
    std::mutex mutex_;
    std::condition_variable cv_;
    std::atomic<bool> stopping_{false};
    std::condition_variable done_cv_;
    std::size_t active_ = 0;
};
