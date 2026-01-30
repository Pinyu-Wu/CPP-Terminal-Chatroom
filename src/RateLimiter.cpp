#include "RateLimiter.hpp"

RateLimiter::RateLimiter(int maxRequests, std::chrono::milliseconds window)
    : max_(maxRequests), window_(window)
{
}

bool RateLimiter::allow(int key)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto now = Clock::now();
    auto &bucket = buckets_[key];

    if (bucket.count == 0)
    {
        bucket.window_start = now;
    }

    auto elapsed = now - bucket.window_start;
    if (elapsed >= window_)
    {
        bucket.count = 0;
        bucket.window_start = now;
    }

    bucket.count += 1;
    return bucket.count <= max_;
}
