#!/usr/bin/env bash
# Host harness: every run owns a fresh, network-disabled disposable container.
set -euo pipefail
cd "$(dirname "$0")/../../.."
BIN="$(realpath "${1:-out/linux/ctfir}")"
IMAGE="${CTFIR_EXAM_IMAGE:-centos:7}"
NAME="ctfir-marker-exam-$$-$RANDOM"
RESULTS="${CTFIR_TEST_OUTPUT:-$PWD/out/exam-linux}"
mkdir -p "$RESULTS"
cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT INT TERM
# No user data/host config mount; binary and fixtures are strictly read-only.
docker run --name "$NAME" --network none \
  -e CTFIR_DISPOSABLE_LAB=ctfir-exam-084 \
  -v "$BIN:/opt/ctfir:ro" -v "$PWD/tests/practice/exam-hf:/fx:ro" \
  -v "$RESULTS:/out" "$IMAGE" /bin/bash /fx/verify-linux.sh
