@echo off
setlocal EnableExtensions
set OUT=C:\ctfir-test\out-ad-fix
if exist "%OUT%" rmdir /s /q "%OUT%"
mkdir "%OUT%"
C:\ctfir-test\ctfir.exe scan --out "%OUT%" --profile full > C:\ctfir-test\out-ad-fix-stdout.txt 2> C:\ctfir-test\out-ad-fix-stderr.txt
echo EXIT=%ERRORLEVEL%
exit /b %ERRORLEVEL%
