#!/bin/sh

set -eu

HTML_DIR=/usr/share/nginx/html
SRC_DIR=/usr/local/src/ferriskey
CONFIG_FILE="$HTML_DIR/config.json"

rm -rf -- "${HTML_DIR:?}/"* "${HTML_DIR:?}/".[!.]* "${HTML_DIR:?}/"..?*
cp -r "$SRC_DIR"/* "$HTML_DIR"

if [ -f "$CONFIG_FILE" ]; then
  api_url="${API_URL:-}"
  escaped_api_url=$(printf '%s' "$api_url" | sed -e 's/[\/&|]/\\&/g')
  # shellcheck disable=SC2016
  placeholder='${API_URL}'
  sed -i "s|$placeholder|$escaped_api_url|g" "$CONFIG_FILE"

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
  cap_placeholder='${CAP_API_ENDPOINT}'
  sed -i "s|$cap_placeholder|$escaped_cap_api_endpoint|g" "$CONFIG_FILE"
fi

exec "$@"
