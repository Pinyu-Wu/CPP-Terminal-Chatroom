#include <gtest/gtest.h>
#include <chrono>
#include <thread>

#include "RateLimiter.hpp"

TEST(RateLimiterTest, AllowsWithinLimit)
{
    // Ensures the limiter permits requests up to the configured limit within one window.
    RateLimiter limiter(2, std::chrono::milliseconds(100));
    EXPECT_TRUE(limiter.allow(1));
    EXPECT_TRUE(limiter.allow(1));
}

TEST(RateLimiterTest, BlocksAfterLimitAndResets)
{
    // Verifies the limiter blocks once the limit is exceeded and recovers after the window elapses.
    RateLimiter limiter(1, std::chrono::milliseconds(50));
    ASSERT_TRUE(limiter.allow(42));
    EXPECT_FALSE(limiter.allow(42));
    std::this_thread::sleep_for(std::chrono::milliseconds(60));
    EXPECT_TRUE(limiter.allow(42));
}
