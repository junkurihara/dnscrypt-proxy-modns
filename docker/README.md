# Deployment using Docker

## Building a Docker image

Docker image of `dnscrypt-proxy-modns` can be build as

```:bash
$ cd docker
$ docker-compose build
```

A pre-built docker image is also available at [Docker Hub](https://hub.docker.com/r/jqtype/dnscrypt-proxy-modns) (`jqtype/dnscrypt-proxy-modns`).

## Configuration

Add your `dnscrypt-proxy.toml` and filtering config files in `./config/` directory and run it via

```:bash
$ docker-compose up -d
```

Please configure the `ports` section of `docker-compose.yml` as you like to expose the port waiting for incoming Do53 queries.

If you pass `DEBUG=true` as an environment variable, you can see the debug messages for checking the path of queries to the target resolver.
