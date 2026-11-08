#!/usr/bin/env bash
# ctfir Windows 构建（bash 编排正本；禁 .bat——见 TEST_RESULTS #9）
# 要点：单行 cmd 中 %PATH% 在解析期展开（早于 vcvars），故绝不 set PATH；
#       cmake/ninja 用 8.3 短路径直呼（无空格无引号）。
# 产物与构建目录一律 D:\ctfir-build（360 残留驱动删 C 盘 PE——见 #8）。
set -euo pipefail
SRC_WIN='C:\Users\ADMINI~1\DOCUME~1\ZCODE-~1\ctfir'
CMAKE_EXE='C:\PROGRA~2\MICROS~3\2022\BUILDT~1\Common7\IDE\COMMON~1\MICROS~1\CMake\CMake\bin\cmake.exe'
NINJA_EXE='C:\PROGRA~2\MICROS~3\2022\BUILDT~1\Common7\IDE\COMMON~1\MICROS~1\CMake\Ninja\ninja.exe'
BUILD_DIR='D:\ctfir-build\cmake-build'
mkdir -p /d/ctfir-build/cmake-build
cmd //c "call C:\PROGRA~2\MICROS~3\2022\BUILDT~1\VC\AUXILI~1\Build\vcvars64.bat >nul 2>&1 && $CMAKE_EXE -S $SRC_WIN -B $BUILD_DIR -G Ninja -DCMAKE_MAKE_PROGRAM=$NINJA_EXE -DCMAKE_BUILD_TYPE=Release && $CMAKE_EXE --build $BUILD_DIR && echo CMAKE_BUILD_OK && dumpbin /dependents $BUILD_DIR\ctfir.exe && dumpbin /dependents $BUILD_DIR\ctfir-gui.exe && dumpbin /dependents $BUILD_DIR\ctfir_tests.exe"
