cmake_minimum_required(VERSION 3.16)

project(CPPChatroom LANGUAGES CXX)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug CACHE STRING "Choose the type of build." FORCE)
endif()

option(ENABLE_CLANG_TIDY "Run clang-tidy static analysis if available" ON)
set(DEFAULT_ENABLE_SANITIZERS ON)
if(CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")
    # Keep release-ish builds free of sanitizer overhead to make core dumps smaller/cleaner.
    set(DEFAULT_ENABLE_SANITIZERS OFF)
endif()
option(ENABLE_SANITIZERS "Enable address/undefined sanitizers (GCC/Clang)" ${DEFAULT_ENABLE_SANITIZERS})
option(ENABLE_THREAD_SANITIZER "Enable thread sanitizer instrumentation (incompatible with ENABLE_SANITIZERS)" OFF)
option(BUILD_TESTING "Build tests" ON)
option(ENABLE_TEST_CRASH "Include a deliberate crash hook for core dump verification" OFF)

if(ENABLE_THREAD_SANITIZER AND ENABLE_SANITIZERS)
    message(FATAL_ERROR "ThreadSanitizer cannot be used together with address/undefined sanitizers. Disable ENABLE_SANITIZERS to enable thread sanitizer.")
endif()

if(ENABLE_CLANG_TIDY)
    find_program(CLANG_TIDY_EXE NAMES clang-tidy)
    if(CLANG_TIDY_EXE)
        set(CMAKE_CXX_CLANG_TIDY "${CLANG_TIDY_EXE}")
    else()
        message(WARNING "clang-tidy requested but not found; continuing without it.")
    endif()
endif()

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

find_path(SODIUM_INCLUDE_DIR sodium.h)
find_library(SODIUM_LIBRARY NAMES sodium)
if(NOT SODIUM_INCLUDE_DIR OR NOT SODIUM_LIBRARY)
    message(FATAL_ERROR "libsodium not found. Install libsodium-dev or provide SODIUM_INCLUDE_DIR/SODIUM_LIBRARY.")
endif()
add_library(Sodium::Sodium INTERFACE IMPORTED)
target_include_directories(Sodium::Sodium INTERFACE "${SODIUM_INCLUDE_DIR}")
target_link_libraries(Sodium::Sodium INTERFACE "${SODIUM_LIBRARY}")

set(SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/src")
set(INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/include")
set(TEST_DIR "${CMAKE_CURRENT_SOURCE_DIR}/tests")
set(COMMON_SOURCES
    "${SRC_DIR}/ChatManager.cpp"
    "${SRC_DIR}/RateLimiter.cpp"
    "${SRC_DIR}/ThreadPool.cpp"
    "${SRC_DIR}/User.cpp"
    "${SRC_DIR}/UserManager.cpp"
)

add_library(chat_core OBJECT ${COMMON_SOURCES})
target_include_directories(chat_core PUBLIC "${INCLUDE_DIR}")
target_link_libraries(chat_core PUBLIC Threads::Threads OpenSSL::SSL OpenSSL::Crypto Sodium::Sodium)
target_compile_features(chat_core PUBLIC cxx_std_17)
set_target_properties(chat_core PROPERTIES CXX_EXTENSIONS OFF)

function(enable_warnings target_name)
    if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
        target_compile_options(${target_name} PRIVATE -Wall -Wextra -Wpedantic)
    endif()
endfunction()
enable_warnings(chat_core)

if(ENABLE_SANITIZERS AND CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU" AND NOT MSVC)
    set(SANITIZER_FLAGS -fsanitize=address -fsanitize=undefined -fno-omit-frame-pointer)
    function(enable_sanitizers target_name)
        target_compile_options(${target_name} PRIVATE ${SANITIZER_FLAGS})
        target_link_options(${target_name} PRIVATE ${SANITIZER_FLAGS})
    endfunction()
else()
    function(enable_sanitizers target_name)
    endfunction()
endif()

if(ENABLE_THREAD_SANITIZER AND CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU" AND NOT MSVC)
    set(THREAD_SANITIZER_FLAGS -fsanitize=thread -fno-omit-frame-pointer)
    function(enable_thread_sanitizer target_name)
        target_compile_options(${target_name} PRIVATE ${THREAD_SANITIZER_FLAGS})
        target_link_options(${target_name} PRIVATE ${THREAD_SANITIZER_FLAGS})
    endfunction()
else()
    function(enable_thread_sanitizer target_name)
    endfunction()
endif()

if(ENABLE_THREAD_SANITIZER)
    enable_thread_sanitizer(chat_core)
else()
    enable_sanitizers(chat_core)
endif()

add_executable(server "${SRC_DIR}/server.cpp")
enable_warnings(server)
if(ENABLE_THREAD_SANITIZER)
    enable_thread_sanitizer(server)
else()
    enable_sanitizers(server)
endif()
if(ENABLE_TEST_CRASH)
    target_compile_definitions(server PRIVATE ENABLE_TEST_CRASH)
endif()
target_link_libraries(server PRIVATE chat_core)
set_target_properties(server PROPERTIES CXX_EXTENSIONS OFF)

add_executable(client "${SRC_DIR}/client.cpp")
enable_warnings(client)
if(ENABLE_THREAD_SANITIZER)
    enable_thread_sanitizer(client)
else()
    enable_sanitizers(client)
endif()
target_link_libraries(client PRIVATE chat_core)
set_target_properties(client PROPERTIES CXX_EXTENSIONS OFF)

include(CTest)
if(BUILD_TESTING)
    find_package(GTest REQUIRED)
    add_executable(run_tests
        "${TEST_DIR}/chat_manager_test.cpp"
        "${TEST_DIR}/framing_test.cpp"
        "${TEST_DIR}/rate_limiter_test.cpp"
        "${TEST_DIR}/thread_pool_test.cpp"
        "${TEST_DIR}/user_manager_test.cpp"
        "${TEST_DIR}/user_test.cpp"
        "${TEST_DIR}/utils_test.cpp"
    )
    enable_warnings(run_tests)
    if(ENABLE_THREAD_SANITIZER)
        enable_thread_sanitizer(run_tests)
    else()
        enable_sanitizers(run_tests)
    endif()
    target_link_libraries(run_tests PRIVATE chat_core GTest::gtest GTest::gtest_main)
    set_target_properties(run_tests PROPERTIES CXX_EXTENSIONS OFF)
    add_test(NAME unit_tests COMMAND run_tests)
endif()
