@echo off
setlocal EnableExtensions
set OUT=C:\ctfir-test\out-ad-clean
if exist "%OUT%" rmdir /s /q "%OUT%"
mkdir "%OUT%"
C:\ctfir-test\ctfir.exe scan --out "%OUT%" --profile full > C:\ctfir-test\out-ad-clean-stdout.txt 2> C:\ctfir-test\out-ad-clean-stderr.txt
echo EXIT=%ERRORLEVEL%
exit /b %ERRORLEVEL%
