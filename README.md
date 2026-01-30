# CPP Terminal Chatroom

Single-server, multi-client chatroom implemented in modern C++17 for Linux/Unix terminals. Users can register or log in, manage friend lists, and exchange direct messages with basic history persistence via JSON files.

## Architecture Overview
```
Client (TLS)
    |
    v
IO Thread (epoll + TLS)
    |-- JSON framing & parsing
    |-- Rate limiting
    |-- enqueue request
    v
ThreadPool workers
    |-- Request handlers (auth / friends / chat / echo)
    |-- UserManager / ChatManager
    |-- Metrics / Logger
    |-- enqueue response
    v
IO Thread (EPOLLOUT) -> send TLS response -> Client
```
- **Transport:** TLS over TCP (OpenSSL), length-prefixed JSON framing.
- **Concurrency:** `epoll` event loop for I/O, worker `ThreadPool` for request handling.
- **State:** `UserManager` + `ChatManager` backed by JSON files.
- **Security:** libsodium password hashing, basic request rate limiting.

## Project Layout
- `src/server.cpp` – epoll loop, TLS, request dispatch, metrics/logging hooks.
- `src/client.cpp` – terminal client UI and request loop.
- `src/*.cpp` – core modules (chat/user managers, rate limiter, thread pool).
- `include/*.hpp` – public headers (including embedded `json.hpp`).
- `tests/*.cpp` – unit tests (GoogleTest).
- `config/` – TLS certs (`cert.pem`, `key.pem`).
- `data/` – runtime data files (`users.json`, `chat_history.json`).
- `data/seed/` – sample seed data from the original project.
- `data/demo/` – demo dataset used by `docker-compose.demo.yml`.
- `docker/` – entrypoints and demo automation.

## Prerequisites
- g++ or clang++ with C++17 support
- CMake 3.16+ (build generator)
- Linux (server uses `epoll` and requires `<sys/epoll.h>`; macOS/Windows would need a port to `kqueue`/IOCP)
- OpenSSL dev libs (`libssl-dev` or equivalent) and libsodium for password hashing
- GoogleTest dev package (for tests) and `clang-tidy` if you want static analysis

## Build
### CMake (recommended)
```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DENABLE_CLANG_TIDY=ON -DENABLE_SANITIZERS=ON
cmake --build build
```
- `ENABLE_CLANG_TIDY` runs clang-tidy during the build when available.
- `ENABLE_SANITIZERS` injects `-fsanitize=address,undefined` and `-fno-omit-frame-pointer` on GCC/Clang.
- Disable either by setting the flag to `OFF` at configure time.

### Makefile (simple local build)
```bash
make
```
Outputs: `bin/server`, `bin/client`, `bin/run_tests`.

## Tests
Default sanitizer run (ASan/UBSan):
```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DENABLE_SANITIZERS=ON
cmake --build build
ASAN_OPTIONS=detect_leaks=0 ctest --test-dir build --output-on-failure
```

ThreadSanitizer run (mutually exclusive with ASan/UBSan):
```bash
cmake -S . -B build-tsan -DCMAKE_BUILD_TYPE=Debug -DENABLE_SANITIZERS=OFF -DENABLE_THREAD_SANITIZER=ON
cmake --build build-tsan
TSAN_OPTIONS=halt_on_error=1 ctest --test-dir build-tsan --output-on-failure
```

## Run (local)
1) Start the server (listens on the given port):
```bash
./build/server 9000
```
2) Launch one or more clients (pointing to the server host/IP and port):
```bash
./build/client 127.0.0.1 9000
```
Run from the repo root so the server/client can find `config/` and `data/`.

## TLS (self-signed for development)
1) Generate cert/key (already referenced as `cert.pem`/`key.pem`):
```bash
openssl req -x509 -newkey rsa:4096 -keyout config/key.pem -out config/cert.pem -days 365 -nodes -subj "/CN=localhost"
```
2) Start the server from the repo root so it can load `config/cert.pem` and `config/key.pem`.
3) The client will try to verify using `config/cert.pem`; if not found it will skip verification (development only, not recommended).

## Docker
### Server only
```bash
docker compose -f docker-compose.server.yml up --build
```
Server runs on `localhost:9000` by default. Set `PORT` to override.

### Demo (server + 2 auto clients)
```bash
docker compose -f docker-compose.demo.yml up --build
```
Demo uses `data/demo/` as volume-mounted seed data and auto-runs scripted clients.

### Useful environment variables
- Server: `PORT`
- Client: `SERVER_HOST`, `SERVER_PORT`, `AUTO_RUN=1`, `CLIENT_USERNAME`, `CLIENT_PASSWORD`, `CLIENT_FRIEND`, `CLIENT_MESSAGE`

## Client Commands
- `1` / `2` at startup: login or register (passwords sent over TLS; server hashes with libsodium).
- `/listfriends` – Show your friend list.
- `/addfriend <username>` – Add a friend (must exist, cannot add yourself).
- `/chat <username>` – Request a direct chat (must be friends). Shows recent history, then enter messages until `/exit`.
- `/exit` inside chat mode – Leave the current chat; Ctrl+C to quit the client.
- Any other input sends a generic message to the server (currently echoed back).

## Data & Persistence
- Users and friendships: `data/users.json`
- Chat history: `data/chat_history.json`
Both are loaded at startup and rewritten on changes. Sample datasets live in `data/seed/` and `data/demo/`.

## Notes & Limitations
- TLS uses a self-signed development certificate and libsodium password hashing; keep deployments to trusted environments unless hardened.
- No message delivery queue beyond in-memory routing; offline users rely on saved history when they reconnect.
- Server uses an epoll loop for I/O and a worker thread pool for request processing; shared state is guarded by mutexes.

## Quick Reset
To start from a clean slate, stop the server and remove the two JSON files (or edit them), then restart:
```bash
rm -f data/users.json data/chat_history.json
```
