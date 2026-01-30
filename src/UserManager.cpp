#include "UserManager.hpp"
#include <fstream>
#include <stdexcept>
#include <sodium.h>
#include "utils.hpp"

using json = nlohmann::json;

bool UserManager::loadFromFile(const std::string &filename)
{
    std::ifstream inFile(filename);
    if (!inFile)
    {
        std::ofstream outFile(filename);
        if (!outFile)
            return false;
        outFile << "{}";
        return true;
    }

    json j = json::object();
    if (inFile.peek() != std::ifstream::traits_type::eof())
    {
        inFile >> j;
    }

    for (auto &[username, data] : j.items())
    {
        auto password = data["password"].get<std::string>();
        auto friends = data["friends"].get<std::vector<std::string>>();

        auto user = std::make_shared<User>(username, password);
        for (const auto &f : friends)
        {
            user->addFriend(f);
        }
        users_[username] = user;
    }

    return true;
}

bool UserManager::saveToFile(const std::string &filename) const
{
    json j;

    for (const auto &[username, userPtr] : users_)
    {
        json userJson;
        userJson["password"] = userPtr->getPasswordHash();
        userJson["friends"] = std::vector<std::string>(
            userPtr->getFriends().begin(), userPtr->getFriends().end());
        j[username] = userJson;
    }

    std::ofstream outFile(filename);
    if (!outFile)
        return false;

    outFile << j.dump(4); // Pretty-print with 4-space indentation.
    return true;
}

bool UserManager::userExists(const std::string &username) const
{
    return users_.find(username) != users_.end();
}

std::string UserManager::hashPassword(const std::string &password) const
{
    char hash[crypto_pwhash_STRBYTES];
    // Derive a salted hash using libsodium's moderate limits.
    if (crypto_pwhash_str(
            hash,
            password.c_str(),
            password.size(),
            crypto_pwhash_OPSLIMIT_MODERATE,
            crypto_pwhash_MEMLIMIT_MODERATE) != 0)
    {
        throw std::runtime_error("Password hashing failed");
    }
    return std::string(hash);
}

bool UserManager::verifyPassword(const std::string &username, const std::string &password)
{
    auto it = users_.find(username);
    if (it == users_.end())
        return false;

    const std::string &stored = it->second->getPasswordHash();

    // Verify the libsodium hash.
    if (crypto_pwhash_str_verify(stored.c_str(), password.c_str(), password.size()) == 0)
    {
        return true;
    }

    // Legacy fallback: accept one plaintext match and upgrade to a hash.
    // if (stored == password) {
    //     try {
    //         auto new_hash = hashPassword(password);
    //         it->second->setPasswordHash(new_hash);
    //     } catch (...) {
    //         return false;
    //     }
    //     return true;
    // }

    return false;
}

bool UserManager::registerUser(const std::string &username, const std::string &password)
{
    if (userExists(username))
        return false;
    if (!isValidUsername(username) || !isValidPassword(password))
        return false;
    try
    {
        auto hashed = hashPassword(password);
        users_[username] = std::make_shared<User>(username, hashed);
    }
    catch (...)
    {
        return false;
    }
    return true;
}

std::shared_ptr<User> UserManager::getUser(const std::string &username)
{
    auto it = users_.find(username);
    if (it != users_.end())
    {
        return it->second;
    }
    return nullptr;
}
