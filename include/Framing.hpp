#pragma once

#include <arpa/inet.h>
#include <cstdint>
#include <cstring>
#include <string>

// Frames a payload with a 4-byte big-endian length prefix.
inline std::string frame_message(const std::string &payload)
{
    uint32_t len = static_cast<uint32_t>(payload.size());
    uint32_t net_len = htonl(len);
    std::string framed;
    framed.resize(sizeof(uint32_t));
    std::memcpy(framed.data(), &net_len, sizeof(uint32_t));
    framed.append(payload);
    return framed;
}
