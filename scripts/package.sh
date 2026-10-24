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

ROOT="$(pwd)"
DIST="${ROOT}/dist/${ARTIFACT}"
OUTDIR="${ROOT}/dist"

if [ ! -f "$BIN" ]; then
  echo "error: missing $BIN" >&2
  exit 1
fi

rm -rf "$DIST"
mkdir -p "$DIST"

# make_zip <content-dir> <output-zip>  — stores the directory *contents* at the archive root.
make_zip() {
  local src="$1" out="$2"
  if command -v zip >/dev/null 2>&1; then
    ( cd "$src" && zip -qr "$out" . )
  elif command -v python3 >/dev/null 2>&1; then
    python3 - "$src" "$out" <<'PY'
import os, sys, zipfile
src, out = sys.argv[1], sys.argv[2]
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
    for root, _dirs, files in os.walk(src):
        for f in files:
            p = os.path.join(root, f)
            z.write(p, os.path.relpath(p, src))
PY
  elif command -v 7z >/dev/null 2>&1; then
    ( cd "$src" && 7z a -tzip "$out" . >/dev/null )
  else
    echo "error: need one of zip, python3 or 7z to create the archive" >&2
    exit 1
  fi
}

case "$TARGET" in
  *apple-darwin)
    APP="$DIST/AdminPanel.app/Contents/MacOS"
    mkdir -p "$APP"
    cp "$BIN" "$APP/infosteal-verifier"
    cp resources/macos/Info.plist "$DIST/AdminPanel.app/Contents/Info.plist"
    chmod +x "$APP/infosteal-verifier"
    make_zip "$DIST" "${OUTDIR}/infosteal-verifier-${ARTIFACT}.zip"
    ;;
  *windows*)
    cp "$BIN" "$DIST/infosteal-verifier.exe"
    make_zip "$DIST" "${OUTDIR}/infosteal-verifier-${ARTIFACT}.zip"
    ;;
  *)
    cp "$BIN" "$DIST/infosteal-verifier"
    tar -czf "${OUTDIR}/infosteal-verifier-${ARTIFACT}.tar.gz" -C "$DIST" .
    ;;
esac

echo "packaged: ${ARTIFACT}"
ls -lh "$OUTDIR" || true
