# A forked version of dnscrypt-proxy for &mu;ODNS

(See also [https://dns.secarchlab.net/](https://dns.secarchlab.net).)

This repo is a forked version of [`dnscrypt-proxy`](https://github.com/DNSCrypt/dnscrypt-proxy). From the original version, this has been modified to employ a PoC implementation of **&mu;ODNS** that is a **multiple-relay-based anonymization protocol for DNS queries**.

&mu;ODNS has been designed to protect user privacy in DNS even if a relay(s) collude with a resolver(s), which cannot be solved in existing DNS anonymization protocols. For the detailed information of &mu;ODNS, please refer to our concept paper below:

> Jun Kurihara and Takeshi Kubo, ''Mutualized oblivious DNS (&mu;ODNS): Hiding a tree in the wild forest,'' Apr. 2021. [https://arxiv.org/abs/2104.13785](https://arxiv.org/abs/2104.13785)

Our PoC &mu;ODNS relays have been implemented as a fork of [`encrypted-dns-server`](https://github.com/jedisct1/encrypted-dns-server) and are available at [https://github.com/junkurihara/encrypted-dns-server-modns](https://github.com/junkurihara/encrypted-dns-server-modns). Publicly available relays for PoC &mu;ODNS are listed at [https://github.com/junkurihara/experimental-resolvers](https://github.com/junkurihara/experimental-resolvers).

Docker image of `dnscrypt-proxy-modns` is available at [DockerHub](https://hub.docker.com/r/jqtype/dnscrypt-proxy-modns). See `docker/README.md` for the configuration.

> **If you are interested in &mu;ODNS based on Oblivious DNS over HTTPS, please check my repo of [`doh-auth-proxy`](https://github.com/junkurihara/doh-auth-proxy)**. Note that it is actually a 'work-in-progress' project as well as this repo, and your contribution is really welcome.

> **NOTE**: **At this time this solution should be considered suitable for research and experimentation.**

---

## How to configure for PoC &mu;ODNS

The PoC implementation of &mu;ODNS has been implemented by extending the Anonymized DNSCrypt protocol of DNSCrypt v2. Original `dnscrypt-proxy` can translate between Do53 and Anonymized DNSCrypt messages. In this manner, `dnscrypt-proxy-modns` translates Do53 DNS messages to/from PoC &mu;ODNS messages.

Our `dnscrypt-proxy-modns` supports almost all the features in the original version. Hence, please refer to the original document for the configuration **except for the anonymization** (`[anonymized_dns]` part in `dnscrypt-proxy.toml`). The configuration for the anonymization is given by overriding the original Anonymized DNSCrypt part in `dnscrypt-proxy.toml`, which can be described as follows.

```:toml
#############################################
#  Anonymized DNS modified for PoC mu-ODNS  #
#############################################

[anonymized_dns]

## Routes are indirect ways to reach DNSCrypt servers.
##
## A route maps a server name ("server_name") to one or more relays that will be
## used to connect to that server.
##
## A relay can be specified as a DNS Stamp (either a relay stamp, or a
## DNSCrypt stamp) or a server name.
##
## The following example routes "example-server-1" via `anon-example-1` or `anon-example-2`,
## and "example-server-2" via the relay whose relay DNS stamp is
## "sdns://gRIxMzcuNzQuMjIzLjIzNDo0NDM".
##
## !!! THESE ARE JUST EXAMPLES !!!
##
## Review the list of available relays from the "relays.md" file, and, for each
## server you want to use, define the relays you want connections to go through.
##
## Carefully choose relays and servers so that they are run by different entities.
##
## "server_name" can also be set to "*" to define a default route, for all servers:
## { server_name='*', via=[{stamp='anon-example-1'}, {stamp='anon-example-2'}] }
##
## If a route is ["*"], the proxy automatically picks relays on a distinct network.
## { server_name='*', via=[{stamp='*'}] } is also an option, but is likely to be suboptimal.

#####################################################
### For privacy enhanced anonymized DNS (mu-ODNS) ###
#####################################################
## If an option specified_nexthop = true and a relay is specified with "nexthop",
## it is selected as a nex-thop relay in the route:
## { server_name='*', via=[{stamp='anon-exmaple-1', nexthop=true}, ...]}
##
## The default value of "nexthop" is false.
## If nexthop flags of all available relays are false, all relays are treated equally.
## If some of them are specified, one of nexthop=true relay is chosen for the nexthop
## relay, and others (subsequent relays) are chosen from the remaining.
## When an option relay_randomization = true, relays are chosen at random.
## When {stamp='*'} is given, nexthop flags for relays can be overridden by explicitly
## specifying nexthop=true.

## Manual selection is always recommended over automatic selection, so that you can
## select (relays,server) pairs that work well and fit your own criteria (close by or
## in different countries, operated by different entities, on distinct ISPs...)

# routes = [
#    { server_name='example-server-1', via=[ { stamp = 'anon-example-1', nexthop = true }, { stamp = 'anon-example-2' }] },
#    { server_name='example-server-2', via=[ { stamp = 'sdns://gRIxMzcuNzQuMjIzLjIzNDo0NDM' }] }
# ]

####################################################
## The following is an example configuration.
## This may work, but you should configure as you need first.
## If you use the below, you should carefully check the list specified in [sources.'relays'].
####################################################
## !!! BELOW IS JUST AN EXAMPLE !!!
####################################################
routes = [
  { server_name = '*', via = [
    # saldns01
    { stamp = 'anon-saldns01-conoha-ipv4', nexthop = true },
    # saldns02
    { stamp = 'anon-saldns02-conoha-ipv4', nexthop = false },
    # saldnssg01
    { stamp = 'anon-saldnssg01-conoha-ipv4', nexthop = false },
    # all available relays from fetched lists specified in [sources.'relays'].
    { stamp = '*' },
  ] },
]

# Skip resolvers incompatible with anonymization instead of using them directly

skip_incompatible = false


# If public server certificates for a non-conformant server cannot be
# retrieved via a relay, try getting them directly. Actual queries
# will then always go through relays.

# direct_cert_fallback = false


# If multiple relays are specified, some of them are randomly chosen when
# a query is issued. The default value is true (randomized).

relay_randomization = true


# If this option is true, one of relays with "nexthop=true" is chosen as the
# nexthop relay (at random if relay_randomization=true).
# If there's no relay with "nexthop=true", the proxy falls back to choose a
# relay with "nexthop=false|nil". The default value is false.
# (This should be true as mu-ODNS.)

specified_nexthop = true


# Maximum number of relays (hops before the destination DNSCrypt server).
# Default value is 1. Must be > 0 and max_relays >= min_relays

max_relays = 3


# Minimum number of relays (hops before the destination DNS server).
# Default value is 1. Must be > 0 and max_relays >= min_relays

min_relays = 1


# If proto_v2 = true, a TLV-like header of smaller size is used, which is not
# compatible with # the original version of Anonymized DNSCrypt.
# If it is false, the proxy will use v1 in which for max_relays = min_relays = 1,
# the protocol is identical to the original Anonymized DNSCrypt (compatible).
# The default value is true.

proto_v2 = true
```

Please refer to the example file `dnscrypt-proxy/example-dnscrypt-proxy.toml`.

Several relays for PoC &mu;ODNS have been deployed as [https://github.com/junkurihara/experimental-resolvers](https://github.com/junkurihara/experimental-resolvers), where lists are included in the `example-dnscrypt-proxy.toml` as ones automatically fetched in the process. Note that the operators or relays and resolvers are identical (us) at this point. You can configure as you like. We highly recommend setting target resolvers to ones operated by another entity. Also note that target resolvers must support `DNSCrypt v2` if you invoke the PoC &mu;ODNS protocol.

Also if you like a `docker` deployment, please check the subdirectory `docker/`. If you want to see debug messages to check routes, set the environment variable `DEBUG=true` when you run it, as:

```:bash
$ DEBUG=true dnscrypt-proxy --config ...
```

---

## Modified parts from the original version

We only modified the following parts from the original repo of `dnscrypt-proxy`:

- modified several `.go` files in `dnscrypt-proxy/`

- add `docker/` directory for docker deployment

> **NOTE**: This repo continuously tracks and reflects changes in the original repo of `dnscrypt-proxy`. At this point, CIs (under `.ci/`) and Github Actions (under `.github/`) in the original repo do not work in this forked repo since their setting is not modified for the forked version yet. Currently they are ignored in this repo. (We are planning to modify and re-add them.)

---

Below is the original README.md.

---

# ![dnscrypt-proxy 2](https://raw.github.com/dnscrypt/dnscrypt-proxy/master/logo.png?3)

[![Financial Contributors on Open Collective](https://opencollective.com/dnscrypt/all/badge.svg?label=financial+contributors)](https://opencollective.com/dnscrypt)
[![DNSCrypt-Proxy Release](https://img.shields.io/github/release/dnscrypt/dnscrypt-proxy.svg?label=Latest%20Release&style=popout)](https://github.com/dnscrypt/dnscrypt-proxy/releases/latest)
[![Build Status](https://github.com/DNSCrypt/dnscrypt-proxy/workflows/CI%20and%20optionally%20publish/badge.svg)](https://github.com/DNSCrypt/dnscrypt-proxy/actions)
![CodeQL scan](https://github.com/DNSCrypt/dnscrypt-proxy/workflows/CodeQL%20scan/badge.svg)
![ShiftLeft Scan](https://github.com/DNSCrypt/dnscrypt-proxy/workflows/ShiftLeft%20Scan/badge.svg)
[![#dnscrypt-proxy:matrix.org](https://img.shields.io/matrix/dnscrypt-proxy:matrix.org.svg?label=DNSCrypt-Proxy%20Matrix%20Chat&server_fqdn=matrix.org&style=popout)](https://matrix.to/#/#dnscrypt-proxy:matrix.org)

## Overview

A flexible DNS proxy, with support for modern encrypted DNS protocols such as [DNSCrypt v2](https://dnscrypt.info/protocol), [DNS-over-HTTPS](https://www.rfc-editor.org/rfc/rfc8484.txt), [Anonymized DNSCrypt](https://github.com/DNSCrypt/dnscrypt-protocol/blob/master/ANONYMIZED-DNSCRYPT.txt) and [ODoH (Oblivious DoH)](https://github.com/DNSCrypt/dnscrypt-resolvers/blob/master/v3/odoh-servers.md).

* **[dnscrypt-proxy documentation](https://dnscrypt.info/doc) ← Start here**
* [DNSCrypt project home page](https://dnscrypt.info/)
* [Discussions](https://github.com/DNSCrypt/dnscrypt-proxy/discussions)
* [DNS-over-HTTPS and DNSCrypt resolvers](https://dnscrypt.info/public-servers)
* [Server and client implementations](https://dnscrypt.info/implementations)
* [DNS stamps](https://dnscrypt.info/stamps)
* [FAQ](https://dnscrypt.info/faq)

## [Download the latest release](https://github.com/dnscrypt/dnscrypt-proxy/releases/latest)

Available as source code and pre-built binaries for most operating systems and architectures (see below).

## Features

* DNS traffic encryption and authentication. Supports DNS-over-HTTPS (DoH) using TLS 1.3, DNSCrypt, Anonymized DNS and ODoH
* Client IP addresses can be hidden using Tor, SOCKS proxies or Anonymized DNS relays
* DNS query monitoring, with separate log files for regular and suspicious queries
* Filtering: block ads, malware, and other unwanted content. Compatible with all DNS services
* Time-based filtering, with a flexible weekly schedule
* Transparent redirection of specific domains to specific resolvers
* DNS caching, to reduce latency and improve privacy
* Local IPv6 blocking to reduce latency on IPv4-only networks
* Load balancing: pick a set of resolvers, dnscrypt-proxy will automatically measure and keep track of their speed, and balance the traffic across the fastest available ones.
* Cloaking: like a `HOSTS` file on steroids, that can return preconfigured addresses for specific names, or resolve and return the IP address of other names. This can be used for local development as well as to enforce safe search results on Google, Yahoo, DuckDuckGo and Bing
* Automatic background updates of resolvers lists
* Can force outgoing connections to use TCP
* Compatible with DNSSEC
* Includes a local DoH server in order to support ECH (ESNI)

## Pre-built binaries

Up-to-date, pre-built binaries are available for:

* Android/arm
* Android/arm64
* Android/x86
* Android/x86_64
* Dragonfly BSD
* FreeBSD/arm
* FreeBSD/x86
* FreeBSD/x86_64
* Linux/arm
* Linux/arm64
* Linux/mips
* Linux/mipsle
* Linux/mips64
* Linux/mips64le
* Linux/x86
* Linux/x86_64
* MacOS X
* NetBSD/x86
* NetBSD/x86_64
* OpenBSD/x86
* OpenBSD/x86_64
* Windows
* Windows 64 bit

How to use these files, as well as how to verify their signatures, are documented in the [installation instructions](https://github.com/dnscrypt/dnscrypt-proxy/wiki/installation).

## Contributors

### Code Contributors

This project exists thanks to all the people who contribute.
<a href="https://github.com/dnscrypt/dnscrypt-proxy/graphs/contributors"><img src="https://opencollective.com/dnscrypt/contributors.svg?width=890&button=false" /></a>

### Financial Contributors

Become a financial contributor and help us sustain our community. [[Contribute](https://opencollective.com/dnscrypt/contribute)]

#### Individuals

<a href="https://opencollective.com/dnscrypt"><img src="https://opencollective.com/dnscrypt/individuals.svg?width=890"></a>

#### Organizations

Support this project with your organization. Your logo will show up here with a link to your website. [[Contribute](https://opencollective.com/dnscrypt/contribute)]

<a href="https://opencollective.com/dnscrypt/organization/0/website"><img src="https://opencollective.com/dnscrypt/organization/0/avatar.svg"></a>
<a href="https://opencollective.com/dnscrypt/organization/1/website"><img src="https://opencollective.com/dnscrypt/organization/1/avatar.svg"></a>
<a href="https://opencollective.com/dnscrypt/organization/2/website"><img src="https://opencollective.com/dnscrypt/organization/2/avatar.svg"></a>
<a href="https://opencollective.com/dnscrypt/organization/3/website"><img src="https://opencollective.com/dnscrypt/organization/3/avatar.svg"></a>
<a href="https://opencollective.com/dnscrypt/organization/4/website"><img src="https://opencollective.com/dnscrypt/organization/4/avatar.svg"></a>
<a href="https://opencollective.com/dnscrypt/organization/5/website"><img src="https://opencollective.com/dnscrypt/organization/5/avatar.svg"></a>
<a href="https://opencollective.com/dnscrypt/organization/6/website"><img src="https://opencollective.com/dnscrypt/organization/6/avatar.svg"></a>
<a href="https://opencollective.com/dnscrypt/organization/7/website"><img src="https://opencollective.com/dnscrypt/organization/7/avatar.svg"></a>
<a href="https://opencollective.com/dnscrypt/organization/8/website"><img src="https://opencollective.com/dnscrypt/organization/8/avatar.svg"></a>
<a href="https://opencollective.com/dnscrypt/organization/9/website"><img src="https://opencollective.com/dnscrypt/organization/9/avatar.svg"></a>
