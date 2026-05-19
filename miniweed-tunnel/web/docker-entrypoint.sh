#!/bin/sh
set -eu

mkdir -p /data

exec node server.js
