#pragma once

#include <iostream>
#include <mutex>
#include <string>

#include "json.hpp"
#include "utils.hpp"

enum class LogLevel
{
    Info,
    Warn,
    Error
};

inline const char *to_string(LogLevel level)
{
    switch (level)
    {
    case LogLevel::Info:
        return "info";
    case LogLevel::Warn:
        return "warn";
    case LogLevel::Error:
        return "error";
    }
    return "unknown";
}

// Thread-safe structured logger that prints one JSON object per line.
class Logger
{
public:
    // Emits a structured log event as a single JSON line.
    static void log_event(LogLevel level, const std::string &action, const std::string &message, const nlohmann::json &extra = nlohmann::json::object())
    {
        nlohmann::json j = extra;
        j["ts"] = current_timestamp();
        j["level"] = to_string(level);
        j["action"] = action;
        j["message"] = message;

        // Serialize output to avoid interleaved JSON lines.
        std::lock_guard<std::mutex> lock(mutex());
        std::cout << j.dump() << std::endl;
    }

private:
    static std::mutex &mutex()
    {
        static std::mutex m;
        return m;
    }
};
