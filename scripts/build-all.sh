#!/usr/bin/env bash
# Cross-compile fwdsvc for every release target.
# Output goes in ./build/. Strips DWARF + symbol table for smaller
# binaries.
set -euo pipefail
cd "$(dirname "$0")/.."

mkdir -p build
LDFLAGS="-s -w"

build() {
  local goos="$1" goarch="$2" goarm="${3-}" outname="$4"
  local env="GOOS=$goos GOARCH=$goarch"
  if [ -n "$goarm" ]; then env="$env GOARM=$goarm"; fi
  echo "==> $outname"
  env $env CGO_ENABLED=0 go build -ldflags="$LDFLAGS" -o "build/$outname" ./cmd/fwdsvc
}

build linux   amd64           ""  fwdsvc-linux-amd64
build linux   arm64           ""  fwdsvc-linux-arm64
build linux   arm             7   fwdsvc-linux-armv7   # Pi 2/3/Zero 2 32-bit
build linux   arm             6   fwdsvc-linux-armv6   # older Pi 1/Zero 1
build windows amd64           ""  fwdsvc-windows-amd64.exe
build darwin  arm64           ""  fwdsvc-darwin-arm64  # Apple silicon

ls -lh build/
