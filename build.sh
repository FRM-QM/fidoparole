#!/usr/bin/env bash
# build.sh — build FidoParole on Linux or macOS.
#
# Builds upstream libfido2 $LIBFIDO2_TAG (USB HID only) and links it
# statically, so the binary never picks up a different system libfido2.
# Also builds fidoparole-bridge, the relay Firefox starts for autofill
# (bridge/). On Linux it is built fully static (musl) when that Rust target
# is installed, so the Flatpak build of Firefox can run it in its sandbox:
#   rustup target add "$(uname -m)-unknown-linux-musl"
#
# Prerequisites
#   Debian/Ubuntu: sudo apt install build-essential cmake pkg-config git \
#                  libcbor-dev libssl-dev zlib1g-dev libudev-dev \
#                  libwebkit2gtk-4.1-dev libgtk-3-dev librsvg2-dev
#   macOS:         brew install cmake pkg-config libcbor openssl@3
#   Rust:          https://rustup.rs
#
# Usage: ./build.sh [--dev] [--rebuild-fido2]
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$HERE"
TAG="${LIBFIDO2_TAG:-1.15.0}"
FIDO="$ROOT/deps/libfido2"
DEV=0; REBUILD=0
for a in "$@"; do
  case "$a" in
    --dev) DEV=1 ;;
    --rebuild-fido2) REBUILD=1 ;;
    *) echo "unknown option $a"; exit 2 ;;
  esac
done

step() { printf '\n\033[36m==> %s\033[0m\n' "$*"; }

# Rebuild when the build configuration changes (the marker records it).
SIG="libfido2 $TAG upstream hid-only v2"
MARK="$FIDO/build/.vault-build"
if [[ $REBUILD == 1 || ! -f "$FIDO/build/src/libfido2.a" || "$(cat "$MARK" 2>/dev/null)" != "$SIG" ]]; then
  step "libfido2 $TAG (upstream, USB HID)"
  if [[ ! -f "$FIDO/CMakeLists.txt" ]]; then
    mkdir -p "$ROOT/deps"
    git clone --depth 1 --branch "$TAG" https://github.com/Yubico/libfido2 "$FIDO"
  fi
  ( cd "$FIDO" && git checkout -- . && git clean -fdq -e build )
  rm -f "$FIDO/build/CMakeCache.txt"
  EXTRA=()
  if [[ "$(uname)" == "Darwin" ]]; then
    OSSL="$(brew --prefix openssl@3)"
    EXTRA+=("-DCMAKE_PREFIX_PATH=$OSSL;$(brew --prefix libcbor)")
    export PKG_CONFIG_PATH="$OSSL/lib/pkgconfig:${PKG_CONFIG_PATH:-}"
  fi
  cmake -S "$FIDO" -B "$FIDO/build" -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_TESTS=OFF -DBUILD_EXAMPLES=OFF -DBUILD_MANPAGES=OFF -DBUILD_TOOLS=OFF \
    -DBUILD_STATIC_LIBS=ON -DBUILD_SHARED_LIBS=ON -DUSE_PCSC=OFF "${EXTRA[@]}"
  cmake --build "$FIDO/build" -j"$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)"
  printf '%s' "$SIG" > "$MARK"
fi

export FIDO2_LIB_DIR="$FIDO/build/src"
export FIDO2_LIB_NAME=fido2
export FIDO2_LINK_STATIC=1
if [[ "$(uname)" == "Darwin" ]]; then
  export RUSTFLAGS="${RUSTFLAGS:-} -L $(brew --prefix openssl@3)/lib -L $(brew --prefix libcbor)/lib"
fi

step "Firefox autofill relay (fidoparole-bridge)"
BRIDGE_TARGET="$ROOT/bridge/target"
RELAY_ARGS=(--release --manifest-path "$ROOT/bridge/Cargo.toml" --target-dir "$BRIDGE_TARGET")
MUSL="$(uname -m)-unknown-linux-musl"
if [[ "$(uname)" == "Linux" ]] && rustup target list --installed 2>/dev/null | grep -qx "$MUSL"; then
  RUSTFLAGS="" cargo build "${RELAY_ARGS[@]}" --target "$MUSL"
  RELAY="$BRIDGE_TARGET/$MUSL/release/fidoparole-bridge"
else
  if [[ "$(uname)" == "Linux" ]]; then
    printf '\033[33mNote: the relay is built without musl. It works with deb/tarball and snap Firefox,\n'
    printf 'but Flatpak Firefox needs the static build: rustup target add %s\033[0m\n' "$MUSL"
  fi
  cargo build "${RELAY_ARGS[@]}"
  RELAY="$BRIDGE_TARGET/release/fidoparole-bridge"
fi

cd "$HERE/src-tauri"
if [[ $DEV == 1 ]]; then
  step "Debug build"
  cargo build
  cp "$RELAY" "${CARGO_TARGET_DIR:-target}/debug/"
  exec "${CARGO_TARGET_DIR:-target}/debug/fidoparole"
fi
step "Release build"
cargo build --release
mkdir -p "$ROOT/dist/fidoparole"
cp "${CARGO_TARGET_DIR:-target}/release/fidoparole" "$RELAY" "$ROOT/dist/fidoparole/"
echo
echo "Built: $ROOT/dist/fidoparole/fidoparole (+ fidoparole-bridge for Firefox autofill)"
[[ "$(uname)" == "Linux" ]] && echo "Linux: install the usual FIDO udev rules so your user can open the key's HID device." || true
