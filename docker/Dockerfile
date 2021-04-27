FROM golang:1-alpine as build

LABEL maintainer "Jun Kurihara"

WORKDIR /tmp

RUN apk --no-cache add git && \
  git clone https://github.com/junkurihara/dnscrypt-proxy-modns dp && \
  cd dp && \
  git checkout multiple_relays && \
  cd dnscrypt-proxy && \
  CGO_ENABLED=0 GOOS=linux go build -a -ldflags '-s -w -extldflags "-static"' -v ./...

FROM alpine:latest

RUN apk --no-cache add ca-certificates python3 git

COPY --from=build /tmp/dp/dnscrypt-proxy/dnscrypt-proxy /usr/local/bin/dnscrypt-proxy
COPY --from=build /tmp/dp/utils/generate-domains-blocklist/generate-domains-blocklist.py /usr/local/bin/generate-domains-blocklist.py
COPY docker/start.sh /usr/local/bin/start.sh

RUN chmod 755 /usr/local/bin/*

VOLUME /config
VOLUME /var/log/dnscrypt-proxy

EXPOSE 53/tcp 53/udp

CMD ["/usr/local/bin/start.sh"]
