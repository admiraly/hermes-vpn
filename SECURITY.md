# Security policy

## Reporting a vulnerability

Please **don't open a public issue** for a security problem. Use GitHub's
private reporting instead: on the repository page choose **Security →
Report a vulnerability** (<https://github.com/admiraly/hermes-vpn/security/advisories/new>).

Include what you found, how to reproduce it, and what an attacker gains.
I'll acknowledge within a few days, keep you updated, and credit you in the
advisory unless you'd rather stay anonymous. This is a one-person project
in alpha: there's no bounty and no formal SLA, but reports are taken
seriously and fixed quickly.

## Scope

In scope: the Hermes engine, daemon, CLI, desktop app, signaling server and
relay server in this repository, and the release workflow.

Particularly interesting: anything that lets a server, the network, or a
non-member read or modify room traffic, impersonate a member, join a room
without its invite code, or escalate privileges through the daemon's local
interface.

Known limitations are listed in [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md)
("Open problems") — reports about those are welcome but already tracked.

## Supported versions

Only the latest release and `master`. Protocol changes that fix security
issues bump the protocol version, so outdated clients and servers refuse to
talk to patched ones rather than silently staying vulnerable.
