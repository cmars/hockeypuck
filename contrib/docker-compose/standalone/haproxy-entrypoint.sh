#!/bin/sh
export HOSTNAME=$(hostname)
export HOST_IP=$(hostname -i)

RELOAD_INTERVAL=${RELOAD_INTERVAL:-1800}

if [ "x${RELOAD_INTERVAL}" != "x0" ]; then
  haproxy "$@" &
  trap exit TERM
  while true; do
    sleep $RELOAD_INTERVAL
    ps | awk '{ if($4 == "haproxy") {print $1} } ' | xargs kill -HUP
  done
else
  exec haproxy "$@"
fi
