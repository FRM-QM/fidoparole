# Build environment for the FidoParole AppImage (see build-appimage.sh).
# Ubuntu 22.04 keeps the glibc baseline at 2.35, so the AppImage runs on any
# current Fedora (incl. Atomic desktops / Universal Blue) and most other distros.
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential ca-certificates curl wget file git cmake pkg-config patchelf \
      libcbor-dev libssl-dev zlib1g-dev libudev-dev \
      libwebkit2gtk-4.1-dev libgtk-3-dev librsvg2-dev \
      libayatana-appindicator3-dev libxdo-dev \
    && rm -rf /var/lib/apt/lists/*

ENV RUSTUP_HOME=/opt/rustup CARGO_HOME=/opt/cargo PATH=/opt/cargo/bin:$PATH
RUN curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable \
    && cargo install tauri-cli --version '^2' --locked \
    && rm -rf /opt/cargo/registry /opt/cargo/git

WORKDIR /work
