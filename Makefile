# ========= Compiler Settings =========
CXX = g++
CPPFLAGS = -Iinclude -MMD -MP
CXXFLAGS = -Wall -Wextra -std=c++17 -pthread
LIBS = -lssl -lcrypto -lsodium
GTEST_LIBS = -lgtest -lgtest_main

# ========= Source Files =========
COMMON_SRC = src/User.cpp src/UserManager.cpp src/ChatManager.cpp src/RateLimiter.cpp src/ThreadPool.cpp
COMMON_HDR = include/User.hpp include/UserManager.hpp include/json.hpp include/ChatManager.hpp include/utils.hpp include/RateLimiter.hpp include/ThreadPool.hpp
TEST_SRC = tests/chat_manager_test.cpp tests/framing_test.cpp tests/rate_limiter_test.cpp tests/user_manager_test.cpp tests/user_test.cpp tests/utils_test.cpp

CLIENT_SRC = src/client.cpp $(COMMON_SRC)
SERVER_SRC = src/server.cpp $(COMMON_SRC)

COMMON_OBJ = $(COMMON_SRC:.cpp=.o)
CLIENT_OBJ = src/client.o $(COMMON_OBJ)
SERVER_OBJ = src/server.o $(COMMON_OBJ)
TEST_OBJ = $(TEST_SRC:.cpp=.o) $(COMMON_OBJ)

CLIENT_BIN = bin/client
SERVER_BIN = bin/server
TEST_BIN = bin/run_tests

# ========= Auto Dependencies =========
DEPS = $(CLIENT_OBJ:.o=.d) $(SERVER_OBJ:.o=.d) $(TEST_OBJ:.o=.d)
-include $(DEPS)

# ========= Targets =========
all: $(CLIENT_BIN) $(SERVER_BIN)

$(CLIENT_BIN): $(CLIENT_OBJ) | bin
	@echo "Compiling client..."
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -o $(CLIENT_BIN) $(CLIENT_OBJ) $(LIBS)

$(SERVER_BIN): $(SERVER_OBJ) | bin
	@echo "Compiling server..."
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -o $(SERVER_BIN) $(SERVER_OBJ) $(LIBS)

tests: $(TEST_BIN)
	@echo "Running unit tests..."
	@./$(TEST_BIN)

$(TEST_BIN): $(TEST_OBJ) | bin
	@echo "Compiling tests..."
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -o $(TEST_BIN) $(TEST_OBJ) $(LIBS) $(GTEST_LIBS)

bin:
	@mkdir -p bin

%.o: %.cpp
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c -o $@ $<

clean:
	@echo "Cleaning up..."
	rm -f $(CLIENT_BIN) $(SERVER_BIN) $(TEST_BIN) $(CLIENT_OBJ) $(SERVER_OBJ) $(TEST_OBJ) $(DEPS)

.PHONY: all clean tests
