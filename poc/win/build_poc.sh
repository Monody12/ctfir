#!/usr/bin/env bash
# ctfir M0 PoC 构建正本（bash 编排）。
# 为什么不是 .bat：本机（360 残留过滤驱动在场）bat 上下文调用 vcvars 全机失效，
# cmd 单行直调稳定可用——证据见 TEST_RESULTS.md 2026-11-08 #9。
# 产物全部落 D:\ctfir-build（C: 上新建 PE 会被 360 残留驱动秒删，见 #8）。
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p /d/ctfir-build

cmd //c 'call C:\PROGRA~2\MICROS~3\2022\BUILDT~1\VC\AUXILI~1\Build\vcvars64.bat >nul 2>&1 && rc poc_gui.rc && cl /nologo /W3 /O2 /MT /EHsc /utf-8 /D_WIN32_WINNT=0x0601 /DWINVER=0x0601 /FoD:\ctfir-build\ /FdD:\ctfir-build\poc.pdb poc_cli.cpp /Fe:D:\ctfir-build\ctfir-poc-cli.exe && cl /nologo /W3 /O2 /MT /EHsc /utf-8 /D_WIN32_WINNT=0x0601 /DWINVER=0x0601 /FoD:\ctfir-build\ /FdD:\ctfir-build\poc.pdb poc_gui.cpp poc_gui.res /link /SUBSYSTEM:WINDOWS /Fe:D:\ctfir-build\ctfir-poc-gui.exe && echo BUILD_OK && echo ==cli-deps== && dumpbin /dependents D:\ctfir-build\ctfir-poc-cli.exe && echo ==gui-deps== && dumpbin /dependents D:\ctfir-build\ctfir-poc-gui.exe' 2>&1 | grep -aiE "BUILD_OK|deps|\.dll|error|失败|不正确" || true

echo "--- 产物存活校验（10 秒后）---"
sleep 10
ls -la /d/ctfir-build/ctfir-poc-cli.exe /d/ctfir-build/ctfir-poc-gui.exe
sha256sum /d/ctfir-build/ctfir-poc-cli.exe /d/ctfir-build/ctfir-poc-gui.exe
