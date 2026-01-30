#include "ChatManager.hpp"
#include <fstream>

std::string ChatManager::makeKey(const std::string& user1, const std::string& user2) {
    return (user1 < user2) ? user1 + "#" + user2 : user2 + "#" + user1;
}

void ChatManager::addMessage(const std::string& user1, const std::string& user2, const std::string& sender, const std::string& message) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::string key = makeKey(user1, user2);
    history_[key].push_back({sender, message, current_timestamp()});
}

std::vector<Message> ChatManager::getHistory(const std::string& user1, const std::string& user2) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::string key = makeKey(user1, user2);
    if (history_.count(key)) {
        return history_[key];
    }
    return {};
}

void ChatManager::saveToFile(const std::string& filename) {
    std::lock_guard<std::mutex> lock(mutex_);
    json j;
    for (const auto& [key, msgs] : history_) {
        for (const auto& m : msgs) {
            j[key].push_back(m.to_json());
        }
    }
    std::ofstream out(filename);
    out << j.dump(4);
}

bool ChatManager::loadFromFile(const std::string& filename) {
    std::ifstream in(filename);
    if (!in.is_open()) {
        std::ofstream out(filename);
        if (!out.is_open()) return false;
        out << "{}";
        return true;
    }

    nlohmann::json j = nlohmann::json::object();
    if (in.peek() != std::ifstream::traits_type::eof()) {
        in >> j;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& [key, msg_list] : j.items()) {
        for (auto& msg : msg_list) {
            history_[key].push_back(Message::from_json(msg));
        }
    }

    return true;
}
