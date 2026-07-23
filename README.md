# 0conf

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
| `src/transport.lisp` | IPv4 multicast UDP (`setsockopt` FFI) | ✅ (IPv6 TODO) |
| `src/responder.lisp` | Listener, answer, probe+conflict-rename, announce, goodbye | ✅ |
| `src/browser.lisp` | `browse` / `browse-once` discovery | ✅ |

## Use

```lisp
(ql:quickload :0conf)   ; or (asdf:load-system :0conf)

;; Discover printers on the LAN for 3s:
(0conf:browse-once "_ipp._tcp.local" :timeout 3.0)

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
- **IPv6:** the codec/records/cache/DNS-SD layers are already address-family
  agnostic (AAAA round-trips today). Only `transport.lisp` is v4-only;
  `make-mdns-socket` dispatches on `:family` so an AF_INET6 socket joining
  `ff02::fb` via `IPV6_JOIN_GROUP` drops in beside it. `parse-ipv6` is still a gap.
- **Character set:** all text is UTF-8 (RFC 6762 §16 / RFC 6763). Names are
  normalized to Unicode NFC on encode via SBCL's built-in `sb-unicode` — so
  composed and decomposed spellings of an accented name go on the wire
  identically — with no external dependency.
- **Negative responses:** `service-info-records` emits NSEC records (instance
  name → SRV+TXT, host name → the address families present) so announcements let
  listeners skip absent types like AAAA on an IPv4-only host. Still TODO: having
  the *responder* attach the matching NSEC when answering a query for a type it
  doesn't hold (proactive denial on demand, not just in announcements).
- **Probing:** the responder probes an instance name three times and, on
  detecting another host answering for it, renames (`Foo` → `Foo (2)`) and
  re-probes (RFC 6762 §8.1, §9). Still TODO: simultaneous-prober lexicographic
  tiebreaking (§8.2) — two hosts probing the same name at the same instant.
- **Remaining TODOs:** on-demand NSEC in query responses, simultaneous-prober
  tiebreaking, randomized 20–120ms response delay, and the deferred-1s
  cache-flush nuance.
