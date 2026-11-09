#!/usr/bin/env bash
# build-appimage.sh — build a self-contained Linux AppImage in Docker.
#
# Output: dist/FidoParole_<version>_amd64.AppImage. It bundles WebKitGTK, GTK,
# libcbor, OpenSSL etc., so it runs on Fedora Atomic desktops / Universal Blue
# (and most other distros with glibc >= 2.35) with nothing layered or installed.
#
# Needs only Docker. Runs from Linux, WSL, or Git Bash on Windows (Docker Desktop).
# libfido2, the cargo registry and the Rust build are cached in Docker volumes;
# `docker volume rm fidoparole-appimage-{deps,registry,target}` resets them.
#
# Usage: ./build-appimage.sh [--rebuild-fido2]
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
IMAGE=fidoparole-appimage
SRC="$ROOT"
if command -v cygpath >/dev/null 2>&1; then
  # Git Bash: hand Docker a Windows path and stop MSYS from rewriting /src etc.
  SRC="$(cygpath -m "$ROOT")"
  export MSYS_NO_PATHCONV=1
fi

docker build -t "$IMAGE" "$SRC/packaging/appimage"
docker run --rm \
  -v "$SRC:/src" \
  -v fidoparole-appimage-deps:/work/deps \
  -v fidoparole-appimage-registry:/opt/cargo/registry \
  -v fidoparole-appimage-target:/cache/target \
  -e CARGO_TARGET_DIR=/cache/target \
  "$IMAGE" bash /src/packaging/appimage/build-in-container.sh "$@"
