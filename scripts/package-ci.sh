#!/usr/bin/env bash
# CI 打装脚本（package.sh 的便携版）：组装单平台发布目录 + SHA256SUMS
# 用法: package-ci.sh --platform windows-x64|linux-x86_64 --ver <版本> --out <staging目录> --bin <可执行文件...>
# zip 由各平台 job 用原生工具完成（windows 用 Compress-Archive，linux 用 zip）
set -euo pipefail
cd "$(dirname "$0")/.."

PLATFORM=""; VER=""; OUT=""; BINS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --platform) PLATFORM="$2"; shift 2;;
    --ver) VER="$2"; shift 2;;
    --out) OUT="$2"; shift 2;;
    --bin) shift; BINS=("$@"); break;;
    *) echo "unknown arg: $1" >&2; exit 2;;
  esac
done
[ -z "$PLATFORM" ] && { echo "--platform required" >&2; exit 2; }
[ -z "$VER" ] && VER="0.0.0"
# 版本串净化（workflow_dispatch 时 ref_name 可能是分支名）
VER=$(printf '%s' "$VER" | tr '/ ' '--')
[ -z "$OUT" ] && OUT="staging"
[ ${#BINS[@]} -eq 0 ] && { echo "--bin required" >&2; exit 2; }

for b in "${BINS[@]}"; do
  [ -f "$b" ] || { echo "binary missing: $b" >&2; exit 1; }
done

rm -rf "$OUT"; mkdir -p "$OUT/licenses"
for b in "${BINS[@]}"; do cp "$b" "$OUT/"; done

# 文档与许可（与本地 package.sh 同清单）
cp packaging/README-先读我.md packaging/COMPATIBILITY.md packaging/KNOWN_LIMITATIONS.md \
   THIRD_PARTY_NOTICES.md LICENSE "$OUT/"
cp licenses/nlohmann-json-MIT.txt "$OUT/licenses/"

STAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)
cat > "$OUT/BUILDINFO.json" <<JSON
{"tool":"ctfir","version":"$VER","built_utc":"$STAMP","schema_version":1,
 "platform":"$PLATFORM","builder":"GitHub Actions (toolchain 同 scripts/build-*.sh)","source":"github.com/Monody12/ctfir"}
JSON
cat > "$OUT/SBOM.json" <<'JSON'
{"components":[
 {"name":"ctfir original code","license":"MIT","origin":"github.com/Monody12/ctfir"},
 {"name":"nlohmann/json","version":"3.12.0","license":"MIT","files":["(静态包含于二进制)"],"hash":"见 DEPENDENCIES.lock.json"},
 {"name":"MSVC v143 /MT CRT 或 musl libc","license":"VS 许可 / MIT","origin":"构建工具链（不随包分发文件）"}
]}
JSON

(cd "$OUT" && find . -type f ! -name SHA256SUMS -exec sha256sum {} \; > SHA256SUMS)
echo "staged $PLATFORM -> $OUT ($(find "$OUT" -type f | wc -l) files)"
