#!/bin/sh
set -eu

mkdir -p /data

if [ "$(id -u)" = "0" ]; then
  chown -R mw:mw /data || true
  chmod -R u+rwX /data || true
  exec su-exec mw:mw node server.js
fi

exec node server.js
