#ifndef USER_HPP
#define USER_HPP

#include <string>
#include <unordered_set>

class User
{
public:
    // Constructor.
    User(const std::string& username, const std::string& password_hash);

    // Getters.
    // Returns the immutable username.
    const std::string& getUsername() const;
    // Returns the stored password hash.
    const std::string& getPasswordHash() const;
    // Indicates whether the user is currently online.
    bool isOnline() const;
    // Returns the current friend list.
    const std::unordered_set<std::string>& getFriends() const;

    // Setters.
    // Sets the online status flag.
    void setOnline(bool status);
    // Replaces the stored password hash.
    void setPasswordHash(const std::string& new_hash);

    // Friend operations.
    // Adds a friend if not already present.
    bool addFriend(const std::string& friendName);
    // Removes a friend if present.
    bool removeFriend(const std::string& friendName);
    // Checks whether a user is in the friend list.
    bool isFriend(const std::string& friendName) const;


private:
std::string username_;
std::string password_hash_;
bool online_;
std::unordered_set<std::string> friend_list_;

};

#endif // USER_HPP
