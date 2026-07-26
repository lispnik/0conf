# mDNS on macOS: the multicast entitlement vs. Local Network privacy

Sending mDNS (multicast to `224.0.0.251:5353` / `ff02::fb`) from your own program
on modern macOS can be blocked by **two different mechanisms**. It's worth knowing
which one you're actually hitting, because the fix is different — and for a
locally-built binary it's almost never the one people reach for first.

## 1. Local Network privacy (TCC) — the one that actually gates you

Since macOS 15, *all* local-network traffic (including multicast) is gated by the
**Local Network** privacy permission. A program that hasn't been granted it gets
its multicast sends silently dropped. This is a per-app runtime permission, not a
code-signing thing.

- **Fix:** System Settings → Privacy & Security → **Local Network**, and enable
  the program (or the terminal you launch it from). If it never appeared, force a
  re-evaluation: `tccutil reset LocalNetwork`, then run the program again.

The built `0conf` CLI works this way: once the terminal/binary has Local Network
access, `0conf browse` discovers real services with no entitlement and no
signing.

## 2. The `com.apple.developer.networking.multicast` entitlement

This entitlement is primarily an **iOS** requirement; on macOS the Local Network
permission above is the real gate for local development. The entitlement matters
for **distribution** (a notarized, Apple-signed app), where Apple must *grant* you
the entitlement first: <https://developer.apple.com/contact/request/networking-multicast>.

`scripts/multicast.entitlements` in this repo is that entitlement, ready for a
proper distribution build.

## Why you can't just codesign the entitlement onto the `0conf` binary

The CLI is built with SBCL's `save-lisp-and-die :executable t`, which **appends
the ~40 MB Lisp core after the Mach-O executable**. That format is incompatible
with code signing:

- `codesign` refuses it — *"main executable failed strict validation"* (exit 1).
  Harmless: it leaves SBCL's own working ad-hoc signature in place.
- `ldid` will embed the entitlement, but it only hashes the Mach-O portion, not
  the appended core. The resulting signature is invalid over the full file, so
  macOS **SIGKILLs the process on launch**. Don't do this.

So: the entitlement cannot be embedded in a `save-lisp-and-die` binary, and it
isn't needed for local use. Grant **Local Network** access (mechanism 1) instead.

If you truly need the signed entitlement (for distribution), don't ship the raw
SBCL executable — build a native launcher/app that is itself signable (and, on
iOS/for the App Store, carries the Apple-granted entitlement in its provisioning
profile).
