#!/usr/bin/env bash
set -euo pipefail

PORT="${PORT:-9000}"

mkdir -p /app/config /app/data
cd /app

printf "{}" > /app/data/users.json
printf "{}" > /app/data/chat_history.json

if [[ ! -f /app/config/cert.pem || ! -f /app/config/key.pem ]]; then
  echo "Generating self-signed TLS cert..."
  openssl req -x509 -newkey rsa:2048 -keyout /app/config/key.pem -out /app/config/cert.pem -days 365 -nodes -subj "/CN=localhost" >/dev/null 2>&1
fi

if [[ ! -f /app/data/users.json ]]; then
  echo "{}" > /app/data/users.json
fi

if [[ ! -f /app/data/chat_history.json ]]; then
  echo "{}" > /app/data/chat_history.json
fi

exec /app/server "${PORT}"
