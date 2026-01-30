#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "json.hpp"

// Fixed-bucket latency histogram in microseconds.
class Histogram
{
public:
    Histogram()
    {
        // Bucket boundaries in microseconds.
        bounds_ = {1000, 5000, 10000, 50000, 100000, 500000, 1000000, 2000000, 5000000};
        counts_.assign(bounds_.size() + 1, 0);
    }

    // Adds a latency observation in microseconds.
    void observe(std::int64_t micros)
    {
        if (micros < 0)
            micros = 0;
        std::lock_guard<std::mutex> lock(mutex_);
        std::size_t idx = 0;
        while (idx < bounds_.size() && micros > bounds_[idx])
        {
            ++idx;
        }
        if (idx >= counts_.size())
            idx = counts_.size() - 1;
        ++counts_[idx];
    }

    struct Snapshot
    {
        std::uint64_t count = 0;
        double p50_ms = 0;
        double p95_ms = 0;
        double p99_ms = 0;
    };

    // Returns a snapshot with count and percentile estimates.
    Snapshot snapshot() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        Snapshot snap;
        snap.count = 0;
        for (auto c : counts_)
            snap.count += c;

        snap.p50_ms = percentile(50);
        snap.p95_ms = percentile(95);
        snap.p99_ms = percentile(99);
        return snap;
    }

private:
    double percentile(int pct) const
    {
        if (counts_.empty())
            return 0.0;
        std::uint64_t total = 0;
        for (auto c : counts_)
            total += c;
        if (total == 0)
            return 0.0;

        std::uint64_t target = (total * pct + 99) / 100; // Round up to the next count.
        std::uint64_t cumulative = 0;
        for (std::size_t i = 0; i < counts_.size(); ++i)
        {
            cumulative += counts_[i];
            if (cumulative >= target)
            {
                std::int64_t upper = (i < bounds_.size()) ? bounds_[i] : bounds_.back();
                return static_cast<double>(upper) / 1000.0; // Convert micros to ms.
            }
        }
        return static_cast<double>(bounds_.back()) / 1000.0;
    }

    std::vector<std::int64_t> bounds_;
    std::vector<std::uint64_t> counts_;
    mutable std::mutex mutex_;
};

class Metrics
{
public:
    Metrics() : last_snapshot_(std::chrono::steady_clock::now()) {}

    // Tracks active connections.
    void inc_connections() { connections_.fetch_add(1, std::memory_order_relaxed); }
    void dec_connections() { connections_.fetch_sub(1, std::memory_order_relaxed); }

    // Records a request occurrence by action name.
    void inc_request(const std::string &action)
    {
        total_requests_.fetch_add(1, std::memory_order_relaxed);
        window_requests_.fetch_add(1, std::memory_order_relaxed);
        std::lock_guard<std::mutex> lock(map_mutex_);
        action_counts_[action]++;
    }

    // Records a request latency for the given action.
    void observe_latency(const std::string &action, std::chrono::microseconds duration)
    {
        std::lock_guard<std::mutex> lock(map_mutex_);
        auto &hist = action_latencies_[action];
        hist.observe(duration.count());
    }

    // Produces a metrics snapshot and resets the window counters.
    nlohmann::json snapshot_and_reset_window()
    {
        auto now = std::chrono::steady_clock::now();
        double secs = std::chrono::duration_cast<std::chrono::microseconds>(now - last_snapshot_).count() / 1'000'000.0;
        if (secs <= 0.0)
            secs = 1e-6;

        std::uint64_t window = window_requests_.exchange(0);
        double qps = window / secs;

        nlohmann::json actions = nlohmann::json::object();
        {
            std::lock_guard<std::mutex> lock(map_mutex_);
            for (const auto &kv : action_counts_)
            {
                nlohmann::json entry;
                entry["count"] = kv.second;
                Histogram::Snapshot snap;
                auto hist_it = action_latencies_.find(kv.first);
                if (hist_it != action_latencies_.end())
                {
                    snap = hist_it->second.snapshot();
                }
                entry["p50_ms"] = snap.p50_ms;
                entry["p95_ms"] = snap.p95_ms;
                entry["p99_ms"] = snap.p99_ms;
                actions[kv.first] = entry;
            }
        }

        last_snapshot_ = now;

        nlohmann::json root;
        root["connections"] = connections_.load(std::memory_order_relaxed);
        root["total_requests"] = total_requests_.load(std::memory_order_relaxed);
        root["window_requests"] = window;
        root["qps"] = qps;
        root["actions"] = actions;
        return root;
    }

private:
    std::atomic<int> connections_{0};
    std::atomic<std::uint64_t> total_requests_{0};
    std::atomic<std::uint64_t> window_requests_{0};

    std::unordered_map<std::string, std::uint64_t> action_counts_;
    std::unordered_map<std::string, Histogram> action_latencies_;
    std::mutex map_mutex_;

    std::chrono::steady_clock::time_point last_snapshot_;
};
