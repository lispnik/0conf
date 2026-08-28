# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`0conf` — a pure Common Lisp implementation of mDNS (RFC 6762) and DNS-SD (RFC 6763).
**SBCL only**: the transport uses `sb-bsd-sockets` plus `sb-alien` FFI (`setsockopt`,
`getifaddrs`, `if_nametoindex`). No CFFI, no C shim, no non-SBCL portability layer.

## Commands

Dependencies come from [ocicl](https://github.com/ocicl/ocicl) (`ocicl.csv` is the lockfile;
`ocicl/` is vendored and gitignored). `~/.sbclrc` already loads the ocicl runtime and adds
the cwd to the ASDF source registry, so plain `sbcl` finds the systems from the repo root.

```sh
ocicl install                                        # restore deps
sbcl --non-interactive --eval '(asdf:test-system :0conf)'   # full suite (~58 checks)
scripts/build-cli.sh                                 # build ./0conf (--sign on macOS; see below)
sbcl --non-interactive --load scripts/coverage.lisp  # sb-cover HTML -> coverage/
python3 scripts/coverage-summary.py                  # per-file expression-coverage table
```

Run one test (FiveAM; bind the two timing specials the way `run-tests` does, or a
responder test will really sleep):

```sh
sbcl --non-interactive \
  --eval '(asdf:load-system :0conf/test)' \
  --eval '(let ((0conf::*response-delay* nil) (0conf::*announce-interval* 0))
            (fiveam:run! (quote 0conf/test::responder-answers-query-over-loopback)))'
```

The literate tutorial is the source of truth in `doc/tutorial.org`; `doc/tutorial.lisp` is
tangled output and gitignored — never edit it. CI tangles and runs it, so the tutorial can't
drift:

```sh
emacs --batch --eval "(require 'org)" --eval '(org-babel-tangle-file "doc/tutorial.org")'
sbcl --non-interactive --load doc/tutorial.lisp
```

## Systems and file order

Three ASDF systems in `0conf.asd`, all `:serial t` — **a new source file must be added to
the component list in dependency order**, since there are no per-file `:depends-on` entries.

- `0conf` — the library (`src/`), deps: alexandria, nibbles, bordeaux-threads, sb-bsd-sockets.
- `0conf/cli` — `src/cli.lisp` only; `program-op` builds `./0conf` at the repo root,
  entry point `0conf-cli:toplevel`.
- `0conf/test` — `test/`, FiveAM; `test-op` calls `0conf/test::run-tests`, which signals on failure.

All of `src/` lives in the single `#:0conf` package (nickname `#:zeroconf`); only `cli.lisp`
has its own package (`#:0conf-cli`). Every public symbol must be listed in the `:export`
clause of `src/package.lisp` — it is the API surface. All tests live in one FiveAM suite,
`0conf/test::0conf-tests`, defined in `codec-tests.lisp` (the first test component).

## Architecture

The layers stack strictly bottom-up, mirroring python-zeroconf's module split:

- `octets.lisp` — byte cursor (reader/writer) + DNS name encode/decode with **compression
  pointers**, RFC 4343 presentation escaping (so an instance label may contain a dot), NFC
  normalization on both encode and decode via `sb-unicode`, and IPv4/IPv6 parse/format.
- `records.lisp` — CLOS resource records (A, AAAA, PTR, SRV, TXT, NSEC, `unknown-record`)
  with `write-rdata`/`read-record` methods. `rr-cache-flush` is kept separate from `rr-class`;
  the top class bit is masked at the codec boundary (it means "unicast response requested"
  on a query and "cache-flush" on a response).
- `message.lisp` — header + the four sections; `encode-message` / `decode-message`. Also the
  packet-size discipline: `chunk-records` splits a record list into datagram-sized groups by
  *encoding each candidate group to measure it* (name compression makes per-record sizes
  wrong), and `known-answer-query-packets` applies the §7.2 TC-bit split to queries.
- `cache.lisp` — records bucketed by `(name, type, class)` with absolute expiry times.
  TTL 0 = goodbye (remove matching rdata); cache-flush evicts differing records of the same
  bucket **but spares records received in the last second** (RFC 6762 §10.2) so a
  multi-packet response doesn't destroy itself.
- `transport.lisp` — the only OS-touching layer. `list-interfaces` walks `getifaddrs`
  (skipping loopback and point-to-point/VPN tunnels); `make-mdns-socket*` does
  `SO_REUSEPORT`, group join, and `IP_MULTICAST_IF`/`IPV6_MULTICAST_IF` pinning per family.
  The `sockaddr` alien struct layout is platform-divergent (BSD vs Linux) — touch with care.
  `plan-socket-changes` and friends are the *pure* half of interface re-enumeration: they
  diff held sockets against the live NIC list and open/close nothing, which is what makes
  that logic testable without a network. Same split for receive-side interface attribution:
  `recvmsg-datagram` does the syscall, while `control-interface-index` (the `cmsghdr` walk)
  and `parse-sockaddr-peer` are pure over octets. The `cmsghdr` layout differs between
  Darwin and Linux and is held as **data** (`*darwin-cmsg-layout*` / `*linux-cmsg-layout*`)
  precisely so both shapes are tested on whichever platform runs the suite.
- `service-info.lisp` — a `service-info` struct expands to its PTR/SRV/TXT/A/AAAA/NSEC record
  set and reassembles from records on the far side. TXT values may be strings, NIL (keyless),
  or octet vectors (binary values round-trip as bytes).
- `responder.lisp` — the engine. Owns a socket **per interface per family**, one listener
  thread each, plus a cache sweeper and a conflict resolver, all guarded by one lock. Handles
  probe + conflict rename (§8.1/§8.2 lexicographic tiebreaking), post-announcement conflict
  resolution (§9 — detection runs on the listener, the re-probe on the resolver thread, since
  probing sleeps), announce, goodbye, known-answer suppression across continuation packets,
  on-demand NSEC negative responses (§6.1), randomized 20–120ms response delay with
  duplicate-response suppression (§6), and legacy unicast queries (§6.7). Every send path goes
  through `response-packets`, which splits a record set across datagrams (§17).
- `browser.lisp` — `browse-once`/`resolve`/`enumerate-service-types` are one-shot (own socket);
  `browse-services` attaches to a *running responder* and diffs cache snapshots on a poll,
  firing add/update/remove callbacks with backing-off queries and 80%-of-TTL refreshes.
- `0conf.lisp` — just `start`/`stop` over responder + `register-service`.

Cross-thread cache access always goes through the responder lock. `*response-delay*`,
`*announce-interval*`, `*cache-sweep-interval*`, and `*probe-conflict-backoff*` are the
knobs tests rebind to remove real time from the picture.

## Conventions

- The RFCs are the correctness oracle; comments cite the section they implement
  (`§6.7`, `RFC 6763 §9`). Keep that when changing behavior — a rule without a citation
  reads as an accident.
- Tests that need the OS (`make-mdns-socket`, loopback UDP) **skip rather than fail** when the
  sandbox forbids it; the pure suite is what actually guards correctness. Preserve that pattern
  so CI stays green without a multicast fabric. But guard **only the setup** — a `handler-case`
  wrapped around the assertions too will catch FiveAM's own failure condition and report a real
  regression as an environment skip. Several of the older loopback tests still do this.
- FiveAM's `is` evaluates **both** branches of an `or` so it can report on them, so
  `(is (or (null x) (plusp x)))` errors when `x` is nil instead of short-circuiting. Use a
  single predicate — `(is (typep x '(or null (integer 1 *))))` — or compute the boolean first.
- `test/interop-tests.lisp` decodes real captured Bonjour packets. They are deliberately
  meta-query-only traffic (service types, never device names/addresses) — keep any new fixture
  equally free of identifying data.
- Integration tests use unicast UDP on 127.0.0.1, not multicast, so they run everywhere.

## macOS

A raw `sbcl` (and, unsigned, `./0conf`) cannot send mDNS multicast on macOS 15+ until the
binary or its terminal is granted **Local Network** access (Privacy & Security → Local Network,
or `tccutil reset LocalNetwork`). The `com.apple.developer.networking.multicast` entitlement
is *not* the fix here and **cannot** be embedded: `save-lisp-and-die` appends a ~40 MB core
after the Mach-O, which `codesign` rejects. `build-cli.sh --sign` tries and prints this if it
fails. Full explanation in `doc/macos-multicast.md`.

On a multi-homed/VPN host where the default route is a tunnel, pass `:interface "192.168.x.y"`
(or `-i en0` to the CLI) to pick the real LAN NIC for multicast egress.
