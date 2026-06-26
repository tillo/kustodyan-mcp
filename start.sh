#!/bin/sh
set -e

: "${MCP_BEARER_TOKEN:?MCP_BEARER_TOKEN is not set}"
LISTEN_PORT="${LISTEN_PORT:-8080}"
INTERNAL_PORT="${INTERNAL_PORT:-9090}"
export MCP_BEARER_TOKEN LISTEN_PORT INTERNAL_PORT

# Render the nginx config. Only the listed vars are substituted, so nginx's own
# $variables (e.g. $http_authorization, $arg_token) are left intact.
envsubst '${MCP_BEARER_TOKEN} ${LISTEN_PORT} ${INTERNAL_PORT}' \
  < /etc/nginx/nginx.conf.template > /etc/nginx/nginx.conf

# MCP server: streamable HTTP on the loopback INTERNAL_PORT. Respawn if it exits.
(
  while true; do
    KUSTODYAN_MCP_TRANSPORT=http \
    KUSTODYAN_HTTP_HOST=127.0.0.1 \
    KUSTODYAN_HTTP_PORT="${INTERNAL_PORT}" \
      node /app/dist/server.js || true
    echo "kustodyan-mcp exited — restarting in 1s" >&2
    sleep 1
  done
) &

exec nginx -g 'daemon off;'
