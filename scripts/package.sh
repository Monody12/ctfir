#!/usr/bin/env bash
# ctfir 发布打包（WP8）：双平台 ZIP + SHA256SUMS + BUILDINFO + SBOM
set -euo pipefail
cd "$(dirname "$0")/.."
VER="0.6"
STAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)
REL="/d/ctfir-build/release"
rm -rf "$REL"; mkdir -p "$REL/win-x64" "$REL/linux-x86_64"

# ---------- 文档公共 ----------
for d in "$REL/win-x64" "$REL/linux-x86_64"; do
  cp packaging/README-先读我.md packaging/COMPATIBILITY.md packaging/KNOWN_LIMITATIONS.md \
     THIRD_PARTY_NOTICES.md LICENSE "$d/"
  mkdir -p "$d/licenses" && cp licenses/nlohmann-json-MIT.txt "$d/licenses/"
done

# ---------- Windows ----------
cp /d/ctfir-build/cmake-build/ctfir.exe /d/ctfir-build/cmake-build/ctfir-gui.exe "$REL/win-x64/"
# ---------- Linux ----------
cp /d/ctfir-build/linux/ctfir "$REL/linux-x86_64/"

# ---------- 使用说明.html（极简离线）----------
for d in "$REL/win-x64" "$REL/linux-x86_64"; do
cat > "$d/使用说明.html" <<'HTML'
<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8"><title>ctfir 使用说明</title>
<style>body{font-family:"Microsoft YaHei",sans-serif;max-width:860px;margin:24px;line-height:1.7}h1{border-bottom:2px solid #345;padding-bottom:6px}code{background:#f4f4f4;padding:1px 5px}</style></head>
<body><h1>ctfir 使用说明（离线版）</h1>
<p>ctfir 是<b>只读</b>应急扫描工具：不修改系统、不联网、建议仅供人工参考。</p>
<h2>Windows GUI</h2><ol><li>复制目录到目标机本地并核对 SHA256SUMS；</li><li>运行 ctfir-gui.exe → 选输出目录 → 「开始只读扫描」；</li><li>看模块表/发现列表/详情（证据+建议）；点「复制建议」仅复制文本；</li><li>输出目录 report.html 双击离线查看。</li></ol>
<h2>CLI</h2><pre>ctfir doctor
ctfir scan --out 目录
ctfir explain --session 目录 --finding 规则ID
ctfir report --session 目录 --redact</pre>
<h2>退出码</h2><p>0=完整无发现；1=有发现；2=部分/受限；3=致命；（130=取消）。</p>
<h2>权限说明</h2><p>无管理员/root 也能跑；受限模块如实标 PERMISSION_DENIED（不算 PASS）。</p>
<p>详见 README-先读我.md / COMPATIBILITY.md / KNOWN_LIMITATIONS.md。MIT License。</p>
</body></html>
HTML
done

# ---------- BUILDINFO / SBOM ----------
for d in "$REL/win-x64" "$REL/linux-x86_64"; do
cat > "$d/BUILDINFO.json" <<JSON
{"tool":"ctfir","version":"$VER","built_utc":"$STAMP","schema_version":1,"rule_pack":"6.0.0",
 "platform":"$(basename $d)","builder":"scripts/build-*.sh (见仓库)","source":"github.com/Monody12/ctfir"}
JSON
cat > "$d/SBOM.json" <<'JSON'
{"components":[
 {"name":"ctfir original code","license":"MIT","origin":"github.com/Monody12/ctfir"},
 {"name":"nlohmann/json","version":"3.12.0","license":"MIT","files":["(静态包含于二进制)"],"hash":"见 DEPENDENCIES.lock.json"},
 {"name":"MSVC v143 /MT CRT 或 musl libc","license":"VS 许可 / MIT","origin":"构建工具链（不随包分发文件）"}
]}
JSON
done

# ---------- SHA256SUMS ----------
for d in "$REL/win-x64" "$REL/linux-x86_64"; do
  (cd "$d" && find . -type f ! -name SHA256SUMS -exec sha256sum {} \; > SHA256SUMS)
done

# ---------- ZIP ----------
cd "$REL"
if command -v zip >/dev/null 2>&1; then
  zip -qr ctfir-v"$VER"-windows-x64.zip win-x64 && zip -qr ctfir-v"$VER"-linux-x86_64.zip linux-x86_64
else
  powershell -NoProfile -Command "Compress-Archive -Path 'win-x64' -DestinationPath 'ctfir-v$VER-windows-x64.zip' -Force; Compress-Archive -Path 'linux-x86_64' -DestinationPath 'ctfir-v$VER-linux-x86_64.zip' -Force" 2>/dev/null || echo "(zip 不可用，保留目录形态)"
fi
echo "== 发布清单 =="; ls -la "$REL"; echo "== 根 SHA256 =="; sha256sum "$REL"/*.zip 2>/dev/null || true
