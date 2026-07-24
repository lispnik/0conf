# 0conf

[![CI](https://github.com/lispnik/0conf/actions/workflows/ci.yml/badge.svg)](https://github.com/lispnik/0conf/actions/workflows/ci.yml)

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
| `src/transport.lisp` | IPv4 + IPv6 multicast UDP (`setsockopt` FFI) | ✅ |
| `src/responder.lisp` | Listener, answer, probe+conflict-rename, announce, goodbye | ✅ |
| `src/browser.lisp` | `browse-once` snapshot + live async `browse-services` | ✅ |

## Use

```lisp
(ql:quickload :0conf)   ; or (asdf:load-system :0conf)

;; One-shot snapshot — discover printers on the LAN for 3s:
(0conf:browse-once "_ipp._tcp.local" :timeout 3.0)

;; Live browsing — callbacks as services come and go (needs a running responder):
(let* ((r (0conf:start-responder (0conf:make-responder)))
       (b (0conf:browse-services r "_ipp._tcp.local"
            :on-add    (lambda (info) (format t "+ ~A~%" (0conf:service-instance-name info)))
            :on-remove (lambda (name) (format t "- ~A~%" name)))))
  ;; ... later ...
  (0conf:stop-browse b)
  (0conf:stop r))

;; Advertise a service:
(let ((r (0conf:start
          :services (list (0conf:make-service-info
                           :type "_http._tcp.local" :name "My Widget"
                           :host "widget.local" :port 8080
                           :addresses (list (0conf:parse-ipv4 "192.168.1.42"))
                           :txt '(("path" . "/status")))))))
  ;; ... later ...
  (0conf:stop r))
```

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
run: a per-file table is posted to the run summary and the full HTML is uploaded
as the `coverage-html` artifact. Reproduce locally:

```sh
sbcl --non-interactive --load scripts/coverage.lisp   # writes coverage/cover-index.html
python3 scripts/coverage-summary.py                   # prints the summary table
```

The library sources sit around ~70% of expressions; the untested remainder is
mostly the multicast send/receive paths (no live network in CI) and pure
declaration files.

## Develop

Dependencies are managed with [ocicl](https://github.com/ocicl/ocicl):

```sh
ocicl install                             # restore deps from ocicl.csv
sbcl --eval '(asdf:test-system :0conf)'   # 58 checks, all pure + FFI socket
```

The test suite is pure (codec / records / cache / DNS-SD) plus one guarded
socket-construction test; it needs no network and skips the socket test if the
OS forbids binding 5353.

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
- **IPv6:** fully supported — `(make-mdns-socket :family :ipv6)` opens an
  AF_INET6 socket joining `ff02::fb` via `IPV6_JOIN_GROUP`, `mdns-send`/`mdns-recv`
  are family-aware, and `parse-ipv6`/`format-ipv6` handle `::` compression. The
  codec/records/cache/DNS-SD layers were already address-family agnostic.
  (`parse-ipv6` doesn't yet handle embedded-IPv4 `::ffff:1.2.3.4` forms.)
- **Character set:** all text is UTF-8 (RFC 6762 §16 / RFC 6763). Names are
  normalized to Unicode NFC on encode via SBCL's built-in `sb-unicode` — so
  composed and decomposed spellings of an accented name go on the wire
  identically — with no external dependency.
- **Negative responses:** `service-info-records` emits NSEC records (instance
  name → SRV+TXT, host name → the address families present), and the responder
  also attaches them on demand (RFC 6762 §6.1): a positive answer carries the
  name's NSEC in Additional, and a query for a type we don't hold at a name we
  own is answered with the NSEC as a negative response.
- **Response timing & cache-flush:** multicast responses are delayed a random
  20–120ms (§6); cache-flush eviction spares records received within the last
  second so multi-packet responses aren't self-destructive (§10.2).
- **Probing & conflicts:** the responder probes an instance name three times
  and renames (`Foo` → `Foo (2)`) then re-probes on collision (RFC 6762 §8.1,
  §9). Both cases are handled: a *response* means the name is already owned
  (unconditional conflict), and a simultaneous prober's *query* is resolved by
  lexicographic tiebreaking of the proposed record sets (§8.2) — we rename only
  if our data loses.
- **Live browsing:** `browse-services` attaches to a running responder and fires
  add/update/remove callbacks as instances appear, change, and vanish. Discovery
  uses a backing-off PTR query (§5.2) with known-answer suppression; the current
  set is recomputed from the cache on a short poll and diffed. A background
  sweeper expires stale cache entries so removals happen on time. Cross-thread
  cache access is guarded by the responder lock.
- **Remaining TODOs:** embedded-IPv4 IPv6 literals (`::ffff:1.2.3.4`), TTL-refresh
  queries at 80/85/90/95% of ttl for long-lived browses, and CI.
