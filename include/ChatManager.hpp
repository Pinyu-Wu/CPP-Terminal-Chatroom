#pragma once
#include <string>
#include <unordered_map>
#include <vector>
#include <mutex>
#include "json.hpp"
#include "utils.hpp"
using json = nlohmann::json;

struct Message
{
    std::string from;
    std::string content;
    std::string timestamp;

    // Serializes the message for persistence.
    json to_json() const
    {
        return {{"from", from}, {"content", content}, {"timestamp", timestamp}};
    }

    // Builds a message from a JSON object; throws on missing fields.
    static Message from_json(const nlohmann::json &j)
    {
        Message m;
        m.from = j.at("from").get<std::string>();
        m.content = j.at("content").get<std::string>();
        m.timestamp = j.at("timestamp").get<std::string>();
        return m;
    }
};

class ChatManager
{
public:
    // Appends a message to the conversation between two users.
    void addMessage(const std::string &user1, const std::string &user2, const std::string &sender, const std::string &message);
    // Returns a copy of the message history between two users.
    std::vector<Message> getHistory(const std::string &user1, const std::string &user2);
    // Persists all chat history to disk.
    void saveToFile(const std::string &filename);
    // Loads chat history from disk, creating an empty file if missing.
    bool loadFromFile(const std::string &filename);

private:
    std::string makeKey(const std::string &user1, const std::string &user2);
    std::unordered_map<std::string, std::vector<Message>> history_;
    std::mutex mutex_;
};
