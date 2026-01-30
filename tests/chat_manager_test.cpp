#include <gtest/gtest.h>
#include <filesystem>
#include <fstream>

#include "ChatManager.hpp"

TEST(ChatManagerTest, AddMessageStoresChronologically)
{
    // Ensures messages are stored per conversation and order is preserved.
    ChatManager cm;
    cm.addMessage("alice", "bob", "alice", "hi");
    cm.addMessage("bob", "alice", "bob", "hello");
    auto history = cm.getHistory("alice", "bob");
    ASSERT_EQ(history.size(), 2u);
    EXPECT_EQ(history[0].content, "hi");
    EXPECT_EQ(history[1].content, "hello");
    EXPECT_EQ(history[0].from, "alice");
    EXPECT_EQ(history[1].from, "bob");
}

TEST(ChatManagerTest, SaveAndLoadPersistHistory)
{
    // Verifies chat history is persisted and restored from disk.
    ChatManager cm;
    cm.addMessage("alice", "bob", "alice", "ping");
    cm.addMessage("alice", "bob", "bob", "pong");

    auto path = std::filesystem::temp_directory_path() / "chat_manager_test.json";
    cm.saveToFile(path.string());

    ChatManager loaded;
    ASSERT_TRUE(loaded.loadFromFile(path.string()));
    auto history = loaded.getHistory("alice", "bob");
    ASSERT_EQ(history.size(), 2u);
    EXPECT_EQ(history[0].content, "ping");
    EXPECT_EQ(history[1].content, "pong");
    std::filesystem::remove(path);
}
