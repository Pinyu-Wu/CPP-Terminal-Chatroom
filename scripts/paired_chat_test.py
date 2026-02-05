#!/usr/bin/env python3
import argparse
import json
import socket
import ssl
import struct
import threading
import time
from collections import deque

MAX_FRAME_SIZE = 1 << 20


def frame_message(payload: str) -> bytes:
    data = payload.encode("utf-8")
    return struct.pack("!I", len(data)) + data


def parse_frames(buffer: bytearray):
    messages = []
    while True:
        if len(buffer) < 4:
            break
        (length,) = struct.unpack("!I", buffer[:4])
        if length == 0 or length > MAX_FRAME_SIZE:
            raise ValueError(f"Invalid frame length: {length}")
        if len(buffer) < 4 + length:
            break
        payload = bytes(buffer[4 : 4 + length])
        del buffer[: 4 + length]
        messages.append(payload)
    return messages


class Client:
    def __init__(self, host: str, port: int, username: str, password: str, *, verify: bool):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self._sock = None
        self._ssl = None
        self._recv_thread = None
        self._stop = threading.Event()

        self._responses = []
        self._response_cv = threading.Condition()

        self._inbox = []
        self._inbox_cv = threading.Condition()

        self._context = ssl.create_default_context()
        if not verify:
            self._context.check_hostname = False
            self._context.verify_mode = ssl.CERT_NONE

    def connect(self):
        raw_sock = socket.create_connection((self.host, self.port))
        self._sock = raw_sock
        self._ssl = self._context.wrap_socket(raw_sock, server_hostname=self.host)
        self._recv_thread = threading.Thread(target=self._recv_loop, daemon=True)
        self._recv_thread.start()

    def close(self):
        self._stop.set()
        if self._ssl:
            try:
                self._ssl.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                self._ssl.close()
            except OSError:
                pass
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass

    def send_json(self, payload: dict):
        data = json.dumps(payload)
        framed = frame_message(data)
        self._ssl.sendall(framed)

    def request(self, payload: dict, *, predicate=None, timeout: float = 5.0):
        if predicate is None:
            predicate = lambda resp: "status" in resp
        self.send_json(payload)
        return self._wait_response(predicate, timeout)

    def wait_chat_from(self, sender: str, *, timeout: float = 5.0):
        deadline = time.time() + timeout
        with self._inbox_cv:
            while True:
                for idx, msg in enumerate(self._inbox):
                    if msg.get("from") == sender:
                        return self._inbox.pop(idx)
                remaining = deadline - time.time()
                if remaining <= 0:
                    return None
                self._inbox_cv.wait(timeout=remaining)

    def _recv_loop(self):
        buffer = bytearray()
        while not self._stop.is_set():
            try:
                chunk = self._ssl.recv(4096)
            except OSError:
                break
            if not chunk:
                break
            buffer.extend(chunk)
            for payload in parse_frames(buffer):
                try:
                    msg = json.loads(payload.decode("utf-8"))
                except json.JSONDecodeError:
                    continue

                if msg.get("action") == "chat_message":
                    with self._inbox_cv:
                        self._inbox.append(msg)
                        self._inbox_cv.notify_all()
                else:
                    with self._response_cv:
                        self._responses.append(msg)
                        self._response_cv.notify_all()

    def _wait_response(self, predicate, timeout: float):
        deadline = time.time() + timeout
        with self._response_cv:
            while True:
                for idx, resp in enumerate(self._responses):
                    if predicate(resp):
                        return self._responses.pop(idx)
                remaining = deadline - time.time()
                if remaining <= 0:
                    return None
                self._response_cv.wait(timeout=remaining)


def register_or_login(client: Client, retry_delay: float):
    resp = client.request({"action": "register", "username": client.username, "password": client.password})
    if resp is None:
        raise RuntimeError(f"{client.username}: no response to register")
    if resp.get("status") == "success":
        return
    if resp.get("error") == "ERR_USER_EXISTS":
        resp = client.request({"action": "login", "username": client.username, "password": client.password})
        if resp and resp.get("status") == "success":
            return
        raise RuntimeError(f"{client.username}: login failed: {resp}")
    if resp.get("error") == "ERR_AUTH_RATE_LIMIT":
        time.sleep(retry_delay)
        return register_or_login(client, retry_delay)
    raise RuntimeError(f"{client.username}: register failed: {resp}")


def add_friend(client: Client, target: str):
    resp = client.request({"action": "addfriend", "target": target})
    if resp is None:
        raise RuntimeError(f"{client.username}: addfriend timeout")
    if resp.get("status") == "success":
        return True
    if resp.get("error") == "ERR_BAD_REQUEST":
        return True  # already friends or invalid; ok for test flow
    raise RuntimeError(f"{client.username}: addfriend failed: {resp}")


def chat_request(client: Client, target: str):
    resp = client.request({"action": "chat_request", "target": target},
                          predicate=lambda r: r.get("action") == "chat_response")
    if resp is None:
        raise RuntimeError(f"{client.username}: chat_request timeout")
    if resp.get("status") == "success":
        return True
    raise RuntimeError(f"{client.username}: chat_request failed: {resp}")


def chat_roundtrip(a: Client, b: Client, rounds: int, interval: float, timeout: float):
    for i in range(rounds):
        content_a = f"hello {b.username} #{i + 1} from {a.username}"
        a.request({"action": "chat_message", "target": b.username, "content": content_a},
                  predicate=lambda r: r.get("action") == "chat_ack", timeout=timeout)
        msg = b.wait_chat_from(a.username, timeout=timeout)
        if not msg:
            raise RuntimeError(f"{b.username}: did not receive message from {a.username}")

        time.sleep(interval)

        content_b = f"hello {a.username} #{i + 1} from {b.username}"
        b.request({"action": "chat_message", "target": a.username, "content": content_b},
                  predicate=lambda r: r.get("action") == "chat_ack", timeout=timeout)
        msg = a.wait_chat_from(b.username, timeout=timeout)
        if not msg:
            raise RuntimeError(f"{a.username}: did not receive message from {b.username}")

        time.sleep(interval)


def send_marker(client: Client, run_id: str, label: str):
    message = f"TEST_{label} run_id={run_id}"
    client.request({"action": "normal", "message": message}, timeout=2.0)


def main():
    parser = argparse.ArgumentParser(description="Paired TLS chat test for the C++ chat server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=12345)
    parser.add_argument("--pairs", type=int, default=2)
    parser.add_argument("--user-prefix", default="user")
    parser.add_argument("--password", default="pass12345")
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--interval", type=float, default=0.5)
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--verify-cert", action="store_true")
    parser.add_argument("--retry-delay", type=float, default=1.0)
    parser.add_argument("--run-id", default="", help="Run identifier for log markers")
    args = parser.parse_args()

    run_id = args.run_id.strip() or time.strftime("%Y%m%d-%H%M%S")

    total_clients = args.pairs * 2
    if total_clients <= 0:
        raise SystemExit("pairs must be >= 1")

    clients = []
    for i in range(total_clients):
        username = f"{args.user_prefix}{i + 1:03d}"
        client = Client(args.host, args.port, username, args.password, verify=args.verify_cert)
        client.connect()
        clients.append(client)

    try:
        for client in clients:
            register_or_login(client, args.retry_delay)

        send_marker(clients[0], run_id, "START")

        # Add friends in pairs (user001<->user002, user003<->user004, ...)
        for i in range(0, total_clients, 2):
            a = clients[i]
            b = clients[i + 1]
            add_friend(a, b.username)
            add_friend(b, a.username)

        # Optional chat_request to match client workflow.
        for i in range(0, total_clients, 2):
            a = clients[i]
            b = clients[i + 1]
            chat_request(a, b.username)
            chat_request(b, a.username)

        threads = []
        for i in range(0, total_clients, 2):
            a = clients[i]
            b = clients[i + 1]
            t = threading.Thread(target=chat_roundtrip, args=(a, b, args.rounds, args.interval, args.timeout))
            t.start()
            threads.append(t)

        for t in threads:
            t.join()

        send_marker(clients[0], run_id, "END")
    finally:
        for client in clients:
            client.close()


if __name__ == "__main__":
    main()
