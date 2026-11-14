#!/usr/bin/env bash
# Local packages use the same version/provenance metadata as CI. No publishing.
set -euo pipefail
cd "$(dirname "$0")/.."
PYTHON=python3; command -v python3 >/dev/null 2>&1 || PYTHON=python
VER=$("$PYTHON" -c 'import re;print(re.search("kToolVersion = \"(.*?)\"",open("core/model.hpp").read())[1])')
ROOT=${CTFIR_BUILD_ROOT:-/d/ctfir-build}
REL=${CTFIR_RELEASE_OUT:-$ROOT/release}
# Never wipe/overwrite existing artifacts.
[ ! -e "$REL/ctfir-v$VER-windows-x64.zip" ] && [ ! -e "$REL/ctfir-v$VER-linux-x86_64.zip" ] || { echo 'Package already exists'; exit 2; }
mkdir -p "$REL"
for platform in windows-x64 linux-x86_64; do
  STAGE=$(mktemp -d)
  trap 'rm -rf "$STAGE"' EXIT
  if [ "$platform" = windows-x64 ]; then
    bash scripts/package-ci.sh --platform "$platform" --ver "$VER" --out "$STAGE" --bin "$ROOT/cmake-build/ctfir.exe" "$ROOT/cmake-build/ctfir-gui.exe"
  else
    bash scripts/package-ci.sh --platform "$platform" --ver "$VER" --out "$STAGE" --bin "$ROOT/linux/ctfir"
  fi
  "$PYTHON" scripts/zip-utf8.py --root "$STAGE" --out "$REL/ctfir-v$VER-$platform.zip"
  rm -rf "$STAGE"; trap - EXIT
done
(cd "$REL" && sha256sum ctfir-v"$VER"-*.zip > SHA256SUMS.txt)
