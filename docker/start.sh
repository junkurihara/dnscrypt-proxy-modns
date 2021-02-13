#!/bin/sh
echo "start dnscrypt-proxy"

if [ $DEBUG ]; then
  echo "debug mode"
  DEBUG=true exec dnscrypt-proxy -config /config/dnscrypt-proxy.toml
else
  exec dnscrypt-proxy -config /config/dnscrypt-proxy.toml
fi
