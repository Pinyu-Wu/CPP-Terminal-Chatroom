// Utility helpers for timestamps and input validation.
#pragma once
#include <string>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <cctype>

// Returns local time in "YYYY-MM-DD HH:MM:SS" format.
inline std::string current_timestamp() {
    auto now = std::chrono::system_clock::now();
    std::time_t t_c = std::chrono::system_clock::to_time_t(now);

    std::stringstream ss;
    ss << std::put_time(std::localtime(&t_c), "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

inline bool isValidUsername(const std::string &username)
{
    if (username.size() < 3 || username.size() > 20)
        return false;
    for (unsigned char ch : username)
    {
        if (!(std::isalnum(ch) || ch == '_'))
            return false;
    }
    return true;
}

inline bool isValidPassword(const std::string &password)
{
    if (password.size() < 8 || password.size() > 64)
        return false;
    for (unsigned char ch : password)
    {
        if (std::iscntrl(ch))
            return false;
    }
    return true;
}

inline bool isValidMessage(const std::string &msg, std::size_t maxLen = 512)
{
    if (msg.empty() || msg.size() > maxLen)
        return false;
    for (unsigned char ch : msg)
    {
        if (std::iscntrl(ch))
            return false;
    }
    return true;
}
