# 0conf

[![CI](https://github.com/lispnik/0conf/actions/workflows/ci.yml/badge.svg)](https://github.com/lispnik/0conf/actions/workflows/ci.yml)
[![Coverage Status](https://coveralls.io/repos/github/lispnik/0conf/badge.svg?branch=master)](https://coveralls.io/github/lispnik/0conf?branch=master)

A pure Common Lisp implementation of **mDNS** ([RFC 6762](https://www.rfc-editor.org/rfc/rfc6762))
and **DNS-SD** ([RFC 6763](https://www.rfc-editor.org/rfc/rfc6763)) — "zeroconf"
service advertisement and discovery on the local link.

SBCL only (the multicast transport uses `sb-bsd-sockets` + `sb-alien`).

## Layout

| File | Layer | Status |
|------|-------|--------|
| `src/octets.lisp` | Byte cursor + DNS name (de)compression | ✅ |
| `src/records.lisp` | CLOS records: A, AAAA, PTR, SRV, TXT, NSEC | ✅ |
| `src/message.lisp` | DNS header + four sections | ✅ |
| `src/cache.lisp` | TTL cache + cache-flush + goodbye | ✅ |
| `src/service-info.lisp` | DNS-SD expand ↔ reassemble | ✅ |
| `src/transport.lisp` | Per-interface IPv4+IPv6 multicast (`getifaddrs`+`setsockopt` FFI) | ✅ |
| `src/responder.lisp` | Listener, answer, probe+conflict-rename, announce, goodbye | ✅ |
| `src/browser.lisp` | `browse-once` snapshot + live async `browse-services` | ✅ |

## Use

```lisp
(ql:quickload :0conf)   ; or (asdf:load-system :0conf)

;; One-shot snapshot — discover printers on the LAN for 3s:
(0conf:browse-once "_ipp._tcp.local" :timeout 3.0)

;; Resolve one known instance to a service-info (host/port/txt/addresses):
(0conf:resolve "Front Desk Printer._ipp._tcp.local")

;; Live browsing — callbacks as services come and go (needs a running responder):
(let* ((r (0conf:start-responder (0conf:make-responder)))
       (b (0conf:browse-services r "_ipp._tcp.local"
            :on-add    (lambda (info) (format t "+ ~A~%" (0conf:service-instance-name info)))
            :on-remove (lambda (name) (format t "- ~A~%" name)))))
  ;; ... later ...
  (0conf:stop-browse b)
  (0conf:stop r))

;; Advertise a service (:host defaults to this machine's .local name):
(let* ((info (0conf:make-service-info
              :type "_http._tcp.local" :name "My Widget" :port 8080
              :addresses (list (0conf:parse-ipv4 "192.168.1.42"))
              :txt '(("path" . "/status"))))
       (r (0conf:start :services (list info))))
  ;; update the TXT later without re-registering:
  (0conf:update-service-txt r info '(("path" . "/status") ("load" . "0.4")))
  ;; ... later ...
  (0conf:stop r))
```

## Command-line tool

The `0conf/cli` system builds a small standalone `0conf` command:

```sh
scripts/build-cli.sh            # build ./0conf   (add --sign on macOS, see below)

./0conf browse                  # list the DNS-SD service types on the LAN
./0conf browse _airplay._tcp    # list instances of a type (host / port / TXT)
./0conf monitor                 # live, self-updating view of all services (Ctrl-C to quit)
./0conf resolve "Front Desk._ipp._tcp.local"
./0conf publish _http._tcp "My Widget" 8080 --txt path=/status   # advertise until Ctrl-C
./0conf interfaces              # list usable network interfaces (pick a value for -i)
./0conf --version | help
```

**Global options:** `-i/--interface <if>` (pin the egress interface — a NIC name
like `en0`, or the raw form: a dotted-quad for IPv4, an interface index for
IPv6), `--timeout <secs>`, `--json`
(machine-readable output for every command), `--color auto|always|never` (also
honors `NO_COLOR`), and `-6/--ipv6` / `-4/--ipv4` for `browse`/`resolve`.
Exit codes: 0 found, 1 not-found, 2 usage error, 130 on Ctrl-C. When output is
piped or `--json` is set, no ANSI escapes are emitted.

```sh
./0conf browse --json | jq .                 # scriptable
./0conf -i en0 browse _ipp._tcp              # pin the interface (or -i 192.168.1.42)
./0conf monitor --once --timeout 5 --json    # one snapshot, then exit
./0conf monitor --type _googlecast._tcp      # watch just one type
```

`monitor` starts a responder (one socket per interface, so it watches every link;
pin it with `-i`), keeps a live browser per type, and redraws a grouped dashboard
— with an age column — as services appear, change, and disappear, like `dns-sd -B`
/ `avahi-browse -a`. It browses both the types the DNS-SD meta-query enumerates
*and* a built-in list of well-known types (printers, Chromecast, HomeKit, SSH,
SMB, …), since some devices answer a direct browse but ignore the meta-query.
`--once` prints a single snapshot and exits; `--for <secs>` runs for a bounded
time; when piped it streams `+`/`-` add/remove lines instead of a redraw. (On a
client-isolated network — common at cafés — you'll still only see your own device;
that's the access point blocking peer traffic, not the tool.)

`publish` advertises a service (probing + conflict-renaming per RFC 6762) and
sends a goodbye when you stop it; `--txt k=v` (repeatable), `--subtype s`,
`--host h`, `--no-probe`.

`browse` with no argument runs the DNS-SD meta-query
(`_services._dns-sd._udp.local`, [RFC 6763 §9](https://www.rfc-editor.org/rfc/rfc6763#section-9))
to enumerate the service types on the link — the same thing `dns-sd -B` does.

On macOS a raw binary needs Local Network / multicast access to send mDNS:
`scripts/build-cli.sh --sign` ad-hoc-signs the executable with the
`com.apple.developer.networking.multicast` entitlement, and the first run prompts
for Local Network access.

## Tutorial

[`doc/tutorial.org`](doc/tutorial.org) is a literate, tangle-able walkthrough of
the pure API (wire codec, service expansion, cache, reassembly, NFC names). It
tangles into a self-checking `doc/tutorial.lisp`:

```sh
emacs --batch --eval "(require 'org)" --eval '(org-babel-tangle-file "doc/tutorial.org")'
sbcl --non-interactive --load doc/tutorial.lisp     # 15 checks, all self-asserting
```

CI tangles and runs it on every push, so the tutorial can't drift from working code.

## Coverage

CI generates an [`sb-cover`](http://www.sbcl.org/manual/#sb_002dcover) report each
run: a per-file table is posted to the run summary, the full HTML is uploaded as
the `coverage-html` artifact, and the numbers are pushed to
[Coveralls](https://coveralls.io/github/lispnik/0conf). Reproduce locally:

```sh
sbcl --non-interactive --load scripts/coverage.lisp   # writes coverage/cover-index.html
python3 scripts/coverage-summary.py                   # prints the summary table
```

The library proper sits around ~87% of expressions (`octets` 98%, `browser` 94%,
`records` 93%, `service-info` 92%, `transport` 86%); the untested remainder is
mostly the live multicast send/join paths (no multicast fabric in CI) and pure
declaration files. Counting `src/cli.lisp` — barely tested, and mostly terminal
I/O — the whole tree is ~65%.

To post to Coveralls yourself you need `cl-coveralls`, which is deliberately
kept out of `ocicl.csv` (it pulls ~70 systems that only this path wants):

```sh
ocicl install cl-coveralls
COVERALLS=1 sbcl --non-interactive --load scripts/coveralls.lisp
```

The badge reads lower than the table above it: Coveralls scores *lines*, while
`sb-cover` — and so `coverage-summary.py` — scores *expressions*, of which a
line can hold several.

Outside CI that is a dry run — it prints the JSON payload instead of uploading.
CI uploads from the Linux job, authenticating with the `COVERALLS_REPO_TOKEN`
repository secret; the step no-ops when the secret is unavailable, as on a pull
request from a fork.

## Develop

Dependencies are managed with [ocicl](https://github.com/ocicl/ocicl):

```sh
ocicl install                             # restore deps from ocicl.csv
sbcl --eval '(asdf:test-system :0conf)'   # 58 checks, all pure + FFI socket
```

The test suite is mostly pure (codec / records / cache / DNS-SD), plus
loopback-socket integration tests (real send/receive, a full query→responder→
answer flow, `browse-once`, `resolve`), guarded socket-construction tests, and
**interop fixtures** — real mDNS packets captured from Apple's mDNSResponder,
decoded to prove we parse genuine Bonjour wire data (real name compression, the
QU bit, header flags), not just our own encoder's output.

## Platform notes

- **macOS 15+ multicast entitlement.** Sending/receiving multicast requires the
  `com.apple.developer.networking.multicast` entitlement on a signed binary.
  A raw `sbcl` gets **`EHOSTUNREACH` on multicast send** even though routing is
  fine and the entitled system `mDNSResponder` works. Ship 0conf inside a signed
  app bundle that declares the entitlement (and `NSLocalNetworkUsageDescription`)
  for live use; the codec/cache/DNS-SD layers are fully exercised without it.
- **VPN / multi-homed hosts.** If the default route points at a tunnel (e.g.
  Tailscale `utun*`), pass `:interface "192.168.x.y"` to select the real LAN NIC
  for multicast egress (`IP_MULTICAST_IF`).

## Design notes

- **Reference model:** architecture mirrors
  [python-zeroconf](https://github.com/python-zeroconf/python-zeroconf); the wire
  codec follows [mafintosh/dns-packet](https://github.com/mafintosh/dns-packet);
  Apple's [mDNSResponder](https://github.com/apple-oss-distributions/mDNSResponder)
  and the RFCs are the correctness oracle.
- **Per-interface, dual-stack:** `list-interfaces` enumerates usable NICs via
  `getifaddrs` (skipping loopback and point-to-point/VPN tunnels); `start-responder`
  opens one IPv4 and/or IPv6 socket **per interface**, joins the group on that
  specific interface, pins egress to it (`IP_MULTICAST_IF`), runs a listener per
  socket, answers on the socket a query arrived on, and broadcasts announcements
  out every interface — correct on multi-homed / VPN hosts. Best-effort: a failed
  join on one NIC never aborts the others, and it falls back to a single
  all-interfaces socket per family when enumeration yields nothing.
- **Character set & names:** all text is UTF-8 (RFC 6762 §16 / RFC 6763), with
  names normalized to Unicode NFC — on encode *and* decode — via SBCL's built-in
  `sb-unicode` (no external dependency). Names use RFC 4343 presentation escaping,
  so a DNS-SD instance label containing a dot (`My Printer 2.0`) round-trips
  correctly. IPv6 parsing handles `::` compression and embedded-IPv4
  (`::ffff:1.2.3.4`).
- **DNS-SD extras:** service subtypes (`_printer._sub._http._tcp.local`) via a
  `:subtypes` list, and binary TXT values — a TXT value may be an octet vector,
  round-tripping as bytes rather than being forced through UTF-8.
- **Negative responses:** `service-info-records` emits NSEC records (instance
  name → SRV+TXT, host name → the address families present), and the responder
  also attaches them on demand (RFC 6762 §6.1): a positive answer carries the
  name's NSEC in Additional, and a query for a type we don't hold at a name we
  own is answered with the NSEC as a negative response.
- **Response timing & suppression:** answers to all of a query's questions are
  aggregated into one response (§7.4); multicast responses are delayed a random
  20–120ms (§6), extended when the query's TC bit signals more known-answers are
  coming (§7.2); known-answers spanning multiple packets are reassembled per
  source before suppression; and an answer a peer multicasts during our delay is
  dropped (duplicate-response suppression, §6). Cache-flush eviction spares
  records received within the last second so multi-packet responses aren't
  self-destructive (§10.2).
- **Legacy unicast queries (§6.7):** a query from a source port other than 5353
  gets a unicast reply with the query id echoed, the question repeated, and TTLs
  capped at 10s.
- **Probing & conflicts:** the responder probes both the service instance name
  and the host name, renaming on collision (`Foo` → `Foo (2)`, `myhost.local` →
  `myhost-2.local`) and re-probing (RFC 6762 §8.1, §9). Both cases are handled: a
  *response* means the name is already owned (unconditional conflict), and a
  simultaneous prober's *query* is resolved by lexicographic tiebreaking of the
  proposed record sets (§8.2) — we rename only if our data loses.
- **Live browsing:** `browse-services` attaches to a running responder and fires
  add/update/remove callbacks as instances appear, change, and vanish. Discovery
  uses a backing-off PTR query (§5.2) with known-answer suppression, plus
  TTL-refresh queries once a tracked record passes 80% of its lifetime so
  long-watched services don't spuriously expire; the current set is recomputed
  from the cache on a short poll and diffed. A background sweeper expires stale
  cache entries so removals happen on time. Cross-thread cache access is guarded
  by the responder lock.
- **Remaining follow-ups:** dynamic interface re-enumeration (a NIC appearing
  after startup is missed until restart), receive-side interface attribution
  (`IP_PKTINFO`/`IP_RECVIF`), and a socket-count cap on hosts with very many NICs.
