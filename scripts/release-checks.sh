#!/usr/bin/env bash
# Stage-package gate shared by normal CI and tag-release CI. No publishing here.
set -euo pipefail
PLATFORM=$1; BIN=$2
cd "$(dirname "$0")/.."
if [ "$PLATFORM" = windows-x64 ]; then
  PYTHON=python
  export CTFIR_BIN="$BIN"
  "$PYTHON" scripts/scan_bad_escapes.py
  "$PYTHON" tests/test_safety_cli.py "$BIN"
  powershell.exe -NoProfile -NonInteractive -File tests/test_account_review.ps1
  "$PYTHON" tests/fixture_win.py
  "$PYTHON" tests/practice/exam-hf/run_windows.py "$BIN"
  "$BIN" version
  "$PYTHON" scripts/gui-smoke.py "$(dirname "$BIN")/ctfir-gui.exe"
else
  python3 scripts/scan_bad_escapes.py
  BIN=$(realpath "$BIN")
  python3 tests/test_safety_cli.py "$BIN"
  mkdir -p out/release-checks
  for image in alpine:3.20 centos:7 debian:8 ubuntu:16.04; do
    # Pull is test provisioning only. Fixture execution has no network.
    docker image inspect "$image" >/dev/null 2>&1 || docker pull "$image"
    docker run --rm --network none -v "$BIN:/opt/ctfir:ro" \
      -v "$PWD/tests/fixture_linux.sh:/fx.sh:ro" "$image" sh /fx.sh /opt/ctfir
  done
  docker run --rm --network none -v "$BIN:/opt/ctfir:ro" \
    -v "$PWD/tests/fixture_hidepid.sh:/fx.sh:ro" alpine:3.20 sh /fx.sh /opt/ctfir
  CTFIR_TEST_BUILDER=ctfir-builder:ci python3 tests/fixture_linux_hidden.py "$BIN"
  bash tests/practice/exam-hf/run-linux.sh "$BIN"
fi
