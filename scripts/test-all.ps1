# ctfir 全平台一条命令自动化测试（Windows PowerShell 5.1）
# 用法（仓库根）:  powershell -NoProfile -ExecutionPolicy Bypass -File scripts\test-all.ps1
# 环境: CTFIR_SKIP_BUILD=1 跳过构建；CTFIR_SKIP_DOCKER=1 跳过 Linux 容器夹具
$ErrorActionPreference = "Continue"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
if (-not (Test-Path (Join-Path $Root "CMakeLists.txt"))) {
  $Root = (Get-Location).Path
}
Set-Location $Root
$GitBash = "C:\Program Files\Git\bin\bash.exe"
$WinBin = "D:\ctfir-build\cmake-build\ctfir.exe"
$WinTests = "D:\ctfir-build\cmake-build\ctfir_tests.exe"
$LnxBin = "D:\ctfir-build\linux\ctfir"
$LnxTests = "D:\ctfir-build\linux\ctfir_tests"
$env:MSYS_NO_PATHCONV = "1"
$script:Pass = 0
$script:Fail = 0
function Ok([string]$m) { $script:Pass++; Write-Host "[PASS] $m" }
function Bad([string]$m) { $script:Fail++; Write-Host "[FAIL] $m" }

Write-Host "=== ctfir test-all (root=$Root) ==="

if ($env:CTFIR_SKIP_BUILD -ne "1") {
  Write-Host "=== build Windows ==="
  $stampBefore = if (Test-Path $WinBin) { (Get-Item $WinBin).LastWriteTimeUtc } else { [datetime]::MinValue }
  & $GitBash "scripts/build-win.sh"
  $built = (Test-Path $WinBin) -and (Test-Path $WinTests) -and ((Get-Item $WinBin).LastWriteTimeUtc -gt $stampBefore.AddSeconds(2))
  if (-not $built) {
    Write-Host "build-win.sh did not refresh binaries (known Git Bash cmd //c no-op); fallback cmake via vcvars"
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    $vs = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    $vcvars = Join-Path $vs "VC\Auxiliary\Build\vcvars64.bat"
    $cmake = "C:\PROGRA~2\MICROS~3\2022\BUILDT~1\Common7\IDE\COMMON~1\MICROS~1\CMake\CMake\bin\cmake.exe"
    $ninja = "C:\PROGRA~2\MICROS~3\2022\BUILDT~1\Common7\IDE\COMMON~1\MICROS~1\CMake\Ninja\ninja.exe"
    cmd.exe /c "call `"$vcvars`" && `"$cmake`" -S `"$Root`" -B D:\ctfir-build\cmake-build -G Ninja -DCMAKE_MAKE_PROGRAM=$ninja -DCMAKE_BUILD_TYPE=Release && `"$cmake`" --build D:\ctfir-build\cmake-build"
    if ($LASTEXITCODE -ne 0) { Bad "build-win-fallback" } else { Ok "build-win-fallback" }
  } elseif ($LASTEXITCODE -ne 0) { Bad "build-win" } else { Ok "build-win" }
  Write-Host "=== build Linux ==="
  & $GitBash "scripts/build-linux.sh"
  if ($LASTEXITCODE -ne 0) { Bad "build-linux"; } else { Ok "build-linux" }
} else {
  Write-Host "=== skip build (CTFIR_SKIP_BUILD=1) ==="
}

Write-Host "=== scan_bad_escapes ==="
python scripts\scan_bad_escapes.py
if ($LASTEXITCODE -ne 0) { Bad "scan_bad_escapes" } else { Ok "scan_bad_escapes" }

Write-Host "=== Windows unit tests ==="
if (Test-Path $WinTests) {
  & $WinTests
  if ($LASTEXITCODE -ne 0) { Bad "win unit tests" } else { Ok "win unit tests" }
} else { Bad "ctfir_tests.exe missing" }

Write-Host "=== Windows fixture_win.py ==="
$env:CTFIR_BIN = $WinBin
python tests\fixture_win.py
if ($LASTEXITCODE -ne 0) { Bad "fixture_win" } else { Ok "fixture_win" }

if ($env:CTFIR_SKIP_DOCKER -ne "1") {
  Write-Host "=== Linux unit tests (musl, in container if needed) ==="
  if (Test-Path $LnxTests) {
    # linux ELF cannot run on Windows host; run in alpine
    docker run --rm -v "D:/ctfir-build/linux:/t:ro" alpine:3.20 /t/ctfir_tests
    if ($LASTEXITCODE -ne 0) { Bad "linux unit tests" } else { Ok "linux unit tests" }
  } else { Bad "linux ctfir_tests missing" }

  Write-Host "=== Alpine fixture_linux.sh ==="
  docker run --rm --privileged `
    -v "D:/ctfir-build/linux/ctfir:/bin/ctfir:ro" `
    -v "${Root}\tests\fixture_linux.sh:/fx/fixture_linux.sh:ro" `
    alpine:3.20 sh /fx/fixture_linux.sh /bin/ctfir
  if ($LASTEXITCODE -ne 0) { Bad "alpine fixture" } else { Ok "alpine fixture" }

  Write-Host "=== Alpine hidepid (L39) ==="
  docker run --rm --privileged `
    -v "D:/ctfir-build/linux/ctfir:/bin/ctfir:ro" `
    -v "${Root}\tests\fixture_hidepid.sh:/fx/fixture_hidepid.sh:ro" `
    alpine:3.20 sh /fx/fixture_hidepid.sh /bin/ctfir
  if ($LASTEXITCODE -ne 0) { Bad "hidepid fixture" } else { Ok "hidepid fixture" }

  Write-Host "=== centos-ir-lab fixture_builder_centos.sh ==="
  & $GitBash -lc "export MSYS_NO_PATHCONV=1; bash tests/fixture_builder_centos.sh D:/ctfir-build/linux/ctfir"
  if ($LASTEXITCODE -ne 0) { Bad "centos-ir-lab" } else { Ok "centos-ir-lab" }

  Write-Host "=== additional distro userspace (centos:7 / debian:8 / ubuntu:16.04) ==="
  & $GitBash -lc "export MSYS_NO_PATHCONV=1; bash tests/fixture_distros.sh D:/ctfir-build/linux/ctfir tests/fixture_linux.sh"
  if ($LASTEXITCODE -ne 0) { Bad "distro matrix" } else { Ok "distro matrix" }
}

Write-Host "=== test-all 汇总: pass=$($script:Pass) fail=$($script:Fail) ==="
if ($script:Fail -ne 0) { exit 1 } else { exit 0 }
