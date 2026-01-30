#include <gtest/gtest.h>
#include <filesystem>
#include <fstream>
#include <sodium.h>

#include "UserManager.hpp"

class UserManagerTest : public ::testing::Test
{
protected:
    static void SetUpTestSuite()
    {
        // libsodium must be initialized before hashing passwords.
        ASSERT_NE(sodium_init(), -1);
    }
};

TEST_F(UserManagerTest, RegisterAndVerifySucceeds)
{
    // Confirms a newly registered user exists and password verification passes.
    UserManager manager;
    ASSERT_TRUE(manager.registerUser("alice", "StrongPass1"));
    EXPECT_TRUE(manager.userExists("alice"));
    EXPECT_TRUE(manager.verifyPassword("alice", "StrongPass1"));
}

TEST_F(UserManagerTest, DuplicateRegisterFails)
{
    // Ensures duplicate usernames cannot be registered.
    UserManager manager;
    ASSERT_TRUE(manager.registerUser("bob", "AnotherPass1"));
    EXPECT_FALSE(manager.registerUser("bob", "AnotherPass1"));
}

TEST_F(UserManagerTest, InvalidCredentialsRejected)
{
    // Checks invalid usernames/passwords are rejected on registration and verification.
    UserManager manager;
    EXPECT_FALSE(manager.registerUser("ab", "short"));
    EXPECT_FALSE(manager.verifyPassword("ghost", "none"));
}

TEST_F(UserManagerTest, SaveAndLoadRoundTripsUsers)
{
    // Verifies users and friend lists persist correctly to disk and back.
    UserManager manager;
    ASSERT_TRUE(manager.registerUser("alice", "StrongPass1"));
    ASSERT_TRUE(manager.registerUser("bob", "AnotherPass1"));
    manager.getUser("alice")->addFriend("bob");

    auto path = std::filesystem::temp_directory_path() / "user_manager_test.json";
    ASSERT_TRUE(manager.saveToFile(path.string()));

    UserManager reloaded;
    ASSERT_TRUE(reloaded.loadFromFile(path.string()));
    EXPECT_TRUE(reloaded.userExists("alice"));
    auto alice = reloaded.getUser("alice");
    ASSERT_NE(alice, nullptr);
    EXPECT_TRUE(alice->isFriend("bob"));
    std::filesystem::remove(path);
}
