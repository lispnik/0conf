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
  ENT="$(mktemp -t 0conf-multicast).entitlements"
  cat > "$ENT" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
 "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>com.apple.developer.networking.multicast</key>
  <true/>
</dict>
</plist>
PLIST
  echo "Ad-hoc signing ./0conf with the multicast entitlement ..."
  codesign --force --sign - --entitlements "$ENT" --timestamp=none ./0conf
  codesign -d --entitlements - ./0conf 2>/dev/null || true
  rm -f "$ENT"
  echo "Signed.  First run may prompt for Local Network access."
fi
