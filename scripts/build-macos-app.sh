#!/usr/bin/env bash
# Build the native macOS .app bundle locally.
#
#   ./scripts/build-macos-app.sh                 # host arch (arm64 / x86_64)
#   ./scripts/build-macos-app.sh x86_64-apple-darwin
#
# Output: dist/AdminPanel.app
set -euo pipefail

TARGET="${1:-$(rustc -vV | awk '/^host:/{print $2}')}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

BIN="target/${TARGET}/release/infosteal-verifier"
APP="dist/AdminPanel.app"

echo "==> building ${TARGET}"
cargo build --release --locked --target "$TARGET"

if [ ! -f "$BIN" ]; then
  echo "error: missing $BIN" >&2
  exit 1
fi

echo "==> assembling ${APP}"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS"
cp "$BIN" "$APP/Contents/MacOS/infosteal-verifier"
cp resources/macos/Info.plist "$APP/Contents/Info.plist"
chmod +x "$APP/Contents/MacOS/infosteal-verifier"

# Ad-hoc signature so macOS treats the bundle as a locally built app
# instead of an unidentified developer download.
if command -v codesign >/dev/null 2>&1; then
  codesign --force --sign - "$APP" >/dev/null 2>&1 \
    && echo "==> ad-hoc signed" \
    || echo "==> codesign skipped"
fi

echo "==> verifying"
"$APP/Contents/MacOS/infosteal-verifier" --self-test

echo
echo "built: ${APP}"
echo "run:   open ${APP}"
