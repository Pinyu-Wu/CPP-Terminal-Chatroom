#include <gtest/gtest.h>
#include "User.hpp"

TEST(UserTest, FriendOperationsWork)
{
    // Validates friend add/remove operations and deduplication.
    User user("alice", "hash");
    EXPECT_TRUE(user.addFriend("bob"));
    EXPECT_FALSE(user.addFriend("bob"));
    EXPECT_TRUE(user.isFriend("bob"));
    EXPECT_TRUE(user.removeFriend("bob"));
    EXPECT_FALSE(user.isFriend("bob"));
}

TEST(UserTest, OnlineFlagToggles)
{
    // Ensures the online status setter and getter stay consistent.
    User user("alice", "hash");
    EXPECT_FALSE(user.isOnline());
    user.setOnline(true);
    EXPECT_TRUE(user.isOnline());
}
