#!/usr/bin/env bash
# Package the release binary for the current matrix leg.
#   usage: ./scripts/package.sh <rust-target> <artifact-name>
set -euo pipefail

TARGET="${1:?rust target required}"
ARTIFACT="${2:?artifact name required}"
BIN="target/${TARGET}/release/infosteal-verifier"
case "$TARGET" in
  *windows*) BIN="${BIN}.exe" ;;
esac
DIST="dist/${ARTIFACT}"

if [ ! -f "$BIN" ]; then
  echo "error: missing $BIN" >&2
  exit 1
fi

rm -rf "$DIST"
mkdir -p "$DIST"

case "$TARGET" in
  *apple-darwin)
    APP="$DIST/AdminPanel.app/Contents/MacOS"
    mkdir -p "$APP"
    cp "$BIN" "$APP/infosteal-verifier"
    cp resources/macos/Info.plist "$DIST/AdminPanel.app/Contents/Info.plist"
    chmod +x "$APP/infosteal-verifier"
    ( cd "$DIST" && zip -qr "../infosteal-verifier-${ARTIFACT}.zip" "AdminPanel.app" )
    ;;
  *windows*)
    cp "$BIN" "$DIST/infosteal-verifier.exe"
    ( cd "$DIST" && zip -qr "../infosteal-verifier-${ARTIFACT}.zip" . )
    ;;
  *)
    cp "$BIN" "$DIST/infosteal-verifier"
    ( cd "$DIST" && tar -czf "../infosteal-verifier-${ARTIFACT}.tar.gz" . )
    ;;
esac

echo "packaged: ${ARTIFACT}"
ls -lh dist/ || true
