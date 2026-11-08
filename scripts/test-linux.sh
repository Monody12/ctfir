#!/usr/bin/env bash
# ctfir Linux 全链测试：构建 → 单测 → 容器夹具集成测试（正/负/清理复验）
# 注意：管道会吞退出码，构建结果用文件存在性判定
set -euo pipefail
cd "$(dirname "$0")/.."
docker build -f docker/builder.Dockerfile -t ctfir-builder:alpine3.20 . >/dev/null
mkdir -p /d/ctfir-build/linux
MSYS_NO_PATHCONV=1 docker run --rm \
  -v "C:/Users/Administrator/Documents/zcode-projects/ctfir:/src:ro" \
  -v "D:/ctfir-build/linux:/out" \
  ctfir-builder:alpine3.20 sh -c '
    cmake -S /src -B /tmp/build -G Ninja -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_CXX_FLAGS="-static" -DCMAKE_EXE_LINKER_FLAGS="-static" > /tmp/cfg.log 2>&1 &&
    cmake --build /tmp/build > /tmp/build.log 2>&1 &&
    echo ==LINUX_BUILD_OK== &&
    /tmp/build/ctfir_tests > /tmp/unit.log 2>&1 &&
    tail -2 /tmp/unit.log &&
    echo ==LINUX_UNITTEST_OK== &&
    sh /src/tests/fixture_linux.sh /tmp/build/ctfir &&
    echo ==FIXTURE_OK== &&
    cp /tmp/build/ctfir /tmp/build/ctfir_tests /out/ &&
    sha256sum /out/ctfir /out/ctfir_tests
  '
