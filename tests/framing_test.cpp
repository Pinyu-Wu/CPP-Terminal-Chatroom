#include <gtest/gtest.h>
#include <arpa/inet.h>
#include <cstdint>
#include <cstring>

#include "Framing.hpp"

TEST(FramingTest, PrefixesNetworkByteOrderLength)
{
    // Checks the frame carries a 4-byte big-endian length prefix for the payload.
    std::string payload = "hello";
    auto framed = frame_message(payload);
    ASSERT_EQ(framed.size(), sizeof(uint32_t) + payload.size());
    uint32_t net_len = 0;
    std::memcpy(&net_len, framed.data(), sizeof(uint32_t));
    EXPECT_EQ(ntohl(net_len), payload.size());
}

TEST(FramingTest, PreservesPayloadBytes)
{
    // Ensures the payload bytes are appended after the length without alteration.
    std::string payload = R"({"k":"v"})";
    auto framed = frame_message(payload);
    std::string recovered(framed.begin() + sizeof(uint32_t), framed.end());
    EXPECT_EQ(recovered, payload);
}
