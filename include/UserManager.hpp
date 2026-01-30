#ifndef USER_MANAGER_HPP
#define USER_MANAGER_HPP

#include "User.hpp"
#include "json.hpp"

#include <unordered_map>
#include <string>

class UserManager {
public:
    // Loads users from a JSON file.
    bool loadFromFile(const std::string& filename);

    // Saves users to a JSON file.
    bool saveToFile(const std::string& filename) const;

    // User queries and mutations.
    bool userExists(const std::string& username) const;
    // Verifies the supplied password and may upgrade legacy plaintext hashes.
    bool verifyPassword(const std::string& username, const std::string& password);
    // Registers a new user after validation and password hashing.
    bool registerUser(const std::string& username, const std::string& password);
    // Returns the user object if present, otherwise nullptr.
    std::shared_ptr<User> getUser(const std::string& username);

private:
    // Hashes a password using libsodium, throwing on failure.
    std::string hashPassword(const std::string& password) const;
    std::unordered_map<std::string, std::shared_ptr<User>> users_;
};

#endif
