#!/bin/sh
set -eu

if [ -z "${DATABASE_URL:-}" ]; then
  DATABASE_URL="postgresql://${DATABASE_USER:-ferriskey}:${DATABASE_PASSWORD:-ferriskey}@${DATABASE_HOST:-localhost}:${DATABASE_PORT:-5432}/${DATABASE_NAME:-ferriskey}"
fi
export DATABASE_URL

sqlx migrate run --source /usr/local/src/ferriskey/migrations

CONFIG_FILE="/usr/share/nginx/html/config.json"
if [ -f "$CONFIG_FILE" ]; then
  api_url="${API_URL:-}"
  escaped_api_url=$(printf '%s' "$api_url" | sed -e 's/[\/&|]/\\&/g')
  # shellcheck disable=SC2016
  sed -i "s|\${API_URL}|$escaped_api_url|g" "$CONFIG_FILE"

  # Cap widget endpoint for the front. CAP_API_ENDPOINT wins; otherwise derive
  # it from the backend settings, since Cap serves the widget API under
  # <CAP_VERIFY_URL>/<CAP_SITE_KEY>/. Set CAP_API_ENDPOINT explicitly when
  # CAP_VERIFY_URL is an internal address the browser cannot reach.
  cap_api_endpoint="${CAP_API_ENDPOINT:-}"
  if [ -z "$cap_api_endpoint" ] && [ "${CAP_ENABLED:-false}" = "true" ] \
    && [ -n "${CAP_VERIFY_URL:-}" ] && [ -n "${CAP_SITE_KEY:-}" ]; then
    cap_api_endpoint="${CAP_VERIFY_URL%/}/${CAP_SITE_KEY}/"
  fi
  escaped_cap_api_endpoint=$(printf '%s' "$cap_api_endpoint" | sed -e 's/[\/&|]/\\&/g')
  # shellcheck disable=SC2016
  sed -i "s|\${CAP_API_ENDPOINT}|$escaped_cap_api_endpoint|g" "$CONFIG_FILE"
fi

exec /usr/bin/supervisord -c /etc/supervisor/conf.d/ferriskey.conf
