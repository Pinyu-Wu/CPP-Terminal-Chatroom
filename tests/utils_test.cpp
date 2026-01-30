#include <gtest/gtest.h>
#include "utils.hpp"

TEST(UtilsTest, ValidUsernameAccepted)
{
    // Confirms acceptable usernames that match length and allowed characters pass validation.
    EXPECT_TRUE(isValidUsername("user_123"));
}

TEST(UtilsTest, InvalidUsernameRejected)
{
    // Ensures short names and names with symbols are rejected.
    EXPECT_FALSE(isValidUsername("ab"));
    EXPECT_FALSE(isValidUsername("bad!name"));
}

TEST(UtilsTest, ValidPasswordAccepted)
{
    // Checks that a normal printable password within bounds is accepted.
    EXPECT_TRUE(isValidPassword("longEnough1"));
}

TEST(UtilsTest, InvalidPasswordRejected)
{
    // Ensures control characters and overly short passwords are blocked.
    EXPECT_FALSE(isValidPassword("short"));
    EXPECT_FALSE(isValidPassword(std::string("bad\nchar")));
}

TEST(UtilsTest, MessageValidationBounds)
{
    // Verifies messages respect size and control character rules.
    EXPECT_TRUE(isValidMessage("hello there"));
    EXPECT_FALSE(isValidMessage(""));
    EXPECT_FALSE(isValidMessage(std::string(600, 'x')));
    EXPECT_FALSE(isValidMessage(std::string("bad\tmsg")));
}
