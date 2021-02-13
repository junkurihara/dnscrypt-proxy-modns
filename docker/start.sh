#!/bin/sh
echo "start dnscrypt-proxy"
DEBUG=true dnscrypt-proxy -config /config/dnscrypt-proxy.toml
