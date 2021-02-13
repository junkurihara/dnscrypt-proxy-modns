#!/bin/sh
echo "start dnscrypt-proxy"
DEBUG=true exec dnscrypt-proxy -config /config/dnscrypt-proxy.toml
