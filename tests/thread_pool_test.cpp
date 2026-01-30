#include <gtest/gtest.h>
#include <atomic>
#include <future>
#include <chrono>
#include <vector>
#include <mutex>

#include "ThreadPool.hpp"

TEST(ThreadPoolTest, ExecutesBurstOfTasksWithoutDrops)
{
    const std::size_t taskCount = 1000;
    std::vector<std::atomic<int>> hits(taskCount);
    for (auto &hit : hits)
    {
        hit.store(0, std::memory_order_relaxed);
    }

    ThreadPool pool(4);

    std::promise<void> allDonePromise;
    auto allDoneFuture = allDonePromise.get_future();
    std::once_flag completionFlag;
    std::atomic<std::size_t> completed{0};

    for (std::size_t i = 0; i < taskCount; ++i)
    {
        pool.post([&, i]()
                  {
                      hits[i].fetch_add(1, std::memory_order_relaxed);
                      if (completed.fetch_add(1, std::memory_order_relaxed) + 1 == taskCount)
                      {
                          std::call_once(completionFlag, [&]()
                                         { allDonePromise.set_value(); });
                      } });
    }

    ASSERT_EQ(allDoneFuture.wait_for(std::chrono::seconds(5)), std::future_status::ready);
    allDoneFuture.get();

    for (const auto &hit : hits)
    {
        EXPECT_EQ(hit.load(std::memory_order_relaxed), 1);
    }
    pool.wait();
}
