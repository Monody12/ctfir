#!/usr/bin/env bash
# Offline musl build; dependencies are provisioned in the test/build container only.
set -euo pipefail
cd "$(dirname "$0")/.."
SRC="$(pwd)"
if command -v cygpath >/dev/null 2>&1; then
  SRC=$(cygpath -m "$SRC")
  OUT=${CTFIR_BUILD_OUT:-D:/ctfir-build/linux}
else
  OUT=${CTFIR_BUILD_OUT:-$PWD/out/linux}
fi
mkdir -p "$OUT"
docker build ${CTFIR_DOCKER_BUILD_ARGS:-} -f docker/builder.Dockerfile -t ctfir-builder:alpine3.20 .
MSYS_NO_PATHCONV=1 docker run --rm --network none -v "$SRC:/src:ro" -v "$OUT:/out" \
  ctfir-builder:alpine3.20 sh -ec '
    cmake -S /src -B /tmp/build -G Ninja -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_CXX_FLAGS="-static" -DCMAKE_EXE_LINKER_FLAGS="-static"
    cmake --build /tmp/build -j 2
    /tmp/build/ctfir_tests
    cp /tmp/build/ctfir /tmp/build/ctfir_tests /out/
    sha256sum /out/ctfir /out/ctfir_tests
  '
