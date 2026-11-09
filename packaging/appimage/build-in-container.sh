#!/usr/bin/env bash
# Runs inside the fidoparole-appimage container (started by build-appimage.sh).
#   /src   the repository (bind mount, read for sources, dist/ written back)
#   /work  container-local copy that is actually built; /work/deps is a cache volume
set -euo pipefail

step() { printf '\n\033[36m==> %s\033[0m\n' "$*"; }

step "Copy sources"
# Never build in /src directly: its deps/ may hold a Windows libfido2 build
# (build.sh runs git clean there), and builds on the bind mount are slow.
tar -C /src --exclude=./.git --exclude=./deps --exclude=./dist \
    --exclude=./src-tauri/target -cf - . | tar -C /work -xf -
# A Windows checkout with core.autocrlf=true has CRLF shell scripts.
find /work -name '*.sh' -exec sed -i 's/\r$//' {} +

cd /work
./build.sh --appimage "$@"

BUNDLE="${CARGO_TARGET_DIR:-/work/src-tauri/target}/release/bundle/appimage"
APPDIR="$(ls -d "$BUNDLE"/*.AppDir)"
step "Checks"
echo "Libraries the AppImage expects from the host system:"
LD_LIBRARY_PATH="$APPDIR/usr/lib" ldd "$APPDIR/usr/bin/fidoparole" \
  | grep -v "$APPDIR" | sed 's/ (0x[0-9a-f]*)//; s/^/  /'
if LD_LIBRARY_PATH="$APPDIR/usr/lib" ldd "$APPDIR/usr/bin/fidoparole" | grep -q 'not found'; then
  echo "error: unresolved libraries"; exit 1
fi
for ai in "$BUNDLE"/*.AppImage; do
  echo "Runtime: $(file -b "$ai" | cut -d, -f1-5)"
  if readelf -d "$ai" 2>/dev/null | grep -q 'libfuse.so.2'; then
    echo "warning: this AppImage runtime needs libfuse.so.2 on the host"
  fi
done

mkdir -p /src/dist
cp "$BUNDLE"/*.AppImage /src/dist/
chmod +x /src/dist/*.AppImage 2>/dev/null || true
echo
for f in "$BUNDLE"/*.AppImage; do echo "Built: dist/$(basename "$f")"; done
