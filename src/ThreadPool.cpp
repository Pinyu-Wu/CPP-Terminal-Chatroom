#include "ThreadPool.hpp"

ThreadPool::ThreadPool(std::size_t threadCount)
{
    if (threadCount == 0)
        threadCount = 1;

    for (std::size_t i = 0; i < threadCount; ++i)
    {
        workers_.emplace_back([this]()
                              { workerLoop(); });
    }
}

ThreadPool::~ThreadPool()
{
    // Stop accepting new tasks and let workers drain the queue.
    stopping_.store(true, std::memory_order_release);
    cv_.notify_all();

    for (auto &t : workers_)
    {
        if (t.joinable())
            t.join();
    }
}

void ThreadPool::post(std::function<void()> task)
{
    {
        std::lock_guard<std::mutex> lock(mutex_);

        // Avoid enqueueing work while shutting down.
        if (stopping_.load(std::memory_order_acquire))
            return;

        tasks_.push(std::move(task));
    }
    cv_.notify_one();
}

void ThreadPool::wait()
{
    std::unique_lock<std::mutex> lock(mutex_);
    done_cv_.wait(lock, [this]()
                  { return tasks_.empty() && active_ == 0; });
}

void ThreadPool::workerLoop()
{
    while (true)
    {
        std::function<void()> task;

        {
            std::unique_lock<std::mutex> lock(mutex_);
            cv_.wait(lock, [this]()
                     { return stopping_.load(std::memory_order_acquire) || !tasks_.empty(); });

            if (stopping_.load(std::memory_order_acquire) && tasks_.empty())
                return;

            task = std::move(tasks_.front());
            tasks_.pop();
            ++active_;
        }

        task();

        {
            std::lock_guard<std::mutex> lock(mutex_);
            --active_;
            if (tasks_.empty() && active_ == 0)
                done_cv_.notify_all();
        }
    }
}
