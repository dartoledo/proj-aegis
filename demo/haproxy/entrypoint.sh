#!/bin/sh
set -e

mkdir -p /var/run/haproxy /etc/haproxy/certs

node /app/hello-server.js &

exec haproxy -W -f /etc/haproxy/haproxy.cfg -db
