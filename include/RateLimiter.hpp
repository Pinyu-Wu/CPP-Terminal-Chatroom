#pragma once
#include <unordered_map>
#include <chrono>
#include <mutex>

class RateLimiter
{
public:
    using Clock = std::chrono::steady_clock;

    // Creates a limiter with a max count per time window.
    RateLimiter(int maxRequests, std::chrono::milliseconds window);

    // Returns true when the key is within its request window.
    bool allow(int key);

private:
    struct Bucket
    {
        int count = 0;
        Clock::time_point window_start{};
    };

    int max_;
    std::chrono::milliseconds window_;
    std::unordered_map<int, Bucket> buckets_;
    std::mutex mutex_;
};
