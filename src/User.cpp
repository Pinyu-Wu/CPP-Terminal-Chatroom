#include "User.hpp"

User::User(const std::string& username, const std::string& password_hash)
    : username_(username), password_hash_(password_hash), online_(false) {}

const std::string& User::getUsername() const {
    return username_;
}

const std::string& User::getPasswordHash() const {
    return password_hash_;
}

void User::setPasswordHash(const std::string& new_hash) {
    password_hash_ = new_hash;
}

bool User::isOnline() const {
    return online_;
}

void User::setOnline(bool status) {
    online_ = status;
}

bool User::addFriend(const std::string& friendName) {
    if (friendName == username_) return false;
    return friend_list_.insert(friendName).second;
}

bool User::removeFriend(const std::string& friendName) {
    if (friendName == username_) return false;
    return friend_list_.erase(friendName) > 0;
}

bool User::isFriend(const std::string& friendName) const {
    return friend_list_.find(friendName) != friend_list_.end();
}

const std::unordered_set<std::string>& User::getFriends() const {
    return friend_list_;
}
