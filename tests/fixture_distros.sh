#!/usr/bin/env bash
# 在多个 Linux 发行版用户态容器中跑同一套 fixture_linux.sh（musl 静态二进制）。
# Docker 共享宿主内核，不能提供 CentOS 7 的 3.10 真内核；本脚本验收的是
# 该发行版用户态（centos:7 = 3.10 时代 glibc/文件系统布局）。
set -uo pipefail
export MSYS_NO_PATHCONV=1
BIN="${1:-}"
FIXTURE="${2:-}"
[ -f "$BIN" ] || { echo "usage: $0 <linux-ctfir> <fixture_linux.sh>"; exit 2; }
[ -f "$FIXTURE" ] || { echo "fixture script missing: $FIXTURE"; exit 2; }

# 转成 Docker Desktop on Windows 接受的 D:/... 绝对路径
abspath() {
  local p="$1"
  if command -v cygpath >/dev/null 2>&1; then
    cygpath -m "$p"
  else
    python -c "import os,sys; print(os.path.abspath(sys.argv[1]).replace('\\\\','/'))" "$p"
  fi
}
BIN=$(abspath "$BIN")
FIXTURE=$(abspath "$FIXTURE")
echo "BIN=$BIN"
echo "FIXTURE=$FIXTURE"

pass=0; fail=0; skip=0
ok(){ pass=$((pass+1)); echo "[PASS] $1"; }
bad(){ fail=$((fail+1)); echo "[FAIL] $1"; }
sk(){ skip=$((skip+1)); echo "[SKIP] $1"; }

run_one() {
  local image="$1"
  echo "=== distro $image ==="
  if ! docker pull "$image" >/tmp/ctfir-pull.log 2>&1; then
    if ! docker pull "$image" >>/tmp/ctfir-pull.log 2>&1; then
      sk "$image pull failed: $(tail -3 /tmp/ctfir-pull.log | tr '\n' ' ')"
      return
    fi
  fi
  if docker run --rm --privileged \
      -v "${BIN}:/opt/ctfir:ro" \
      -v "${FIXTURE}:/opt/fixture.sh:ro" \
      "$image" /bin/sh /opt/fixture.sh /opt/ctfir; then
    ok "$image fixture"
  else
    bad "$image fixture"
  fi
}

run_one "centos:7"
run_one "debian:8"
run_one "ubuntu:16.04"

echo "=== distro 结果: pass=$pass fail=$fail skip=$skip ==="
[ "$fail" -eq 0 ]
