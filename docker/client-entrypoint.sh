#!/usr/bin/env bash
set -euo pipefail

SERVER_HOST="${SERVER_HOST:-chat-server}"
SERVER_PORT="${SERVER_PORT:-9000}"

if [[ "${AUTO_RUN:-0}" != "0" ]]; then
  USERNAME="${CLIENT_USERNAME:-Alice}"
  PASSWORD="${CLIENT_PASSWORD:-11111111}"
  FRIEND="${CLIENT_FRIEND:-Bob}"
  MESSAGE="${CLIENT_MESSAGE:-Hello from ${USERNAME}}"
  exec expect -f /app/auto_chat.expect "${SERVER_HOST}" "${SERVER_PORT}" "${USERNAME}" "${PASSWORD}" "${FRIEND}" "${MESSAGE}"
fi

exec /app/client "${SERVER_HOST}" "${SERVER_PORT}"
