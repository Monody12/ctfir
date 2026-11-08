#!/usr/bin/env bash
# ctfir Linux 构建（Alpine 容器静态 musl；镜像 ctfir-builder:alpine3.20 固定）
# 单次容器内完成：构建 → 单测 → 产物拷回（容器 --rm，跨 run 不保状态）
set -euo pipefail
cd "$(dirname "$0")/.."
docker build -f docker/builder.Dockerfile -t ctfir-builder:alpine3.20 . >/dev/null
mkdir -p /d/ctfir-build/linux
MSYS_NO_PATHCONV=1 docker run --rm \
  -v "C:/Users/Administrator/Documents/zcode-projects/ctfir:/src:ro" \
  -v "D:/ctfir-build/linux:/out" \
  ctfir-builder:alpine3.20 sh -c '
    cmake -S /src -B /tmp/build -G Ninja -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_CXX_FLAGS="-static" -DCMAKE_EXE_LINKER_FLAGS="-static" > /tmp/cfg.log &&
    cmake --build /tmp/build 2>&1 | tail -3 &&
    echo ==LINUX_BUILD_OK== &&
    /tmp/build/ctfir_tests &&
    echo ==LINUX_TESTS_OK== &&
    (ldd /tmp/build/ctfir 2>&1 | head -1 || true) &&
    cp /tmp/build/ctfir /tmp/build/ctfir_tests /out/ &&
    sha256sum /out/ctfir /out/ctfir_tests
  '
