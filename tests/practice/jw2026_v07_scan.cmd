@echo off
REM Win7 remote helper (CRLF). arg1=scan|report
if not exist C:\ctfir-test mkdir C:\ctfir-test
if /I "%~1"=="report" (
  C:\ctfir-test\ctfir.exe report --session C:\ctfir-test\out-jw2026-v07b > C:\ctfir-test\out-jw2026-v07b-report.txt 2>&1
  echo EXIT=%ERRORLEVEL%>> C:\ctfir-test\out-jw2026-v07b-report.txt
  goto :eof
)
C:\ctfir-test\ctfir.exe version > C:\ctfir-test\out-jw2026-v07b-ver.txt 2>&1
C:\ctfir-test\ctfir.exe scan --out C:\ctfir-test\out-jw2026-v07b --profile full 1> C:\ctfir-test\out-jw2026-v07b-stdout.txt 2> C:\ctfir-test\out-jw2026-v07b-stderr.txt
echo EXIT=%ERRORLEVEL%>> C:\ctfir-test\out-jw2026-v07b-stderr.txt
