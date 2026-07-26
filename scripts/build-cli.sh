#!/bin/sh
# Build the standalone `0conf` command-line executable.
#
#   scripts/build-cli.sh            # build ./0conf
#   scripts/build-cli.sh --sign     # build + ad-hoc codesign with the multicast
#                                   # entitlement (macOS, for local mDNS)
#
# Needs SBCL + ocicl (deps resolved from ocicl.csv).
set -eu

cd "$(dirname "$0")/.."

echo "Building 0conf executable ..."
sbcl --non-interactive --eval '(asdf:make :0conf/cli)'

if [ ! -x ./0conf ]; then
  echo "build failed: ./0conf not produced" >&2
  exit 1
fi
echo "Built ./0conf"

if [ "${1:-}" = "--sign" ]; then
  if [ "$(uname)" != "Darwin" ]; then
    echo "--sign is only meaningful on macOS; skipping." >&2
    exit 0
  fi
  # NOTE: an SBCL save-lisp-and-die executable appends its ~40 MB Lisp core AFTER
  # the Mach-O.  codesign rejects that ("main executable failed strict
  # validation"), and ldid embeds the entitlement but only hashes the Mach-O, so
  # the signature is invalid over the full file and macOS SIGKILLs it on launch.
  # In short: the multicast entitlement can't be embedded in this binary.
  #
  # It doesn't need to be: on macOS the gate for mDNS is the *Local Network*
  # privacy permission (TCC), not this entitlement.  See doc/macos-multicast.md.
  ENT="scripts/multicast.entitlements"
  echo "Attempting to codesign ./0conf with $ENT ..."
  if codesign --force --sign - --entitlements "$ENT" --timestamp=none ./0conf 2>/dev/null; then
    echo "Signed."
  else
    cat >&2 <<'NOTE'
codesign could not sign the SBCL executable (appended Lisp core).  This is
expected and does NOT break the binary.  The multicast entitlement cannot be
embedded in a save-lisp-and-die executable.

To let ./0conf do mDNS on macOS, grant it Local Network access instead:
  System Settings -> Privacy & Security -> Local Network  (enable ./0conf or your
  terminal), or run:  tccutil reset LocalNetwork  and re-run the program.
See doc/macos-multicast.md.
NOTE
  fi
fi
