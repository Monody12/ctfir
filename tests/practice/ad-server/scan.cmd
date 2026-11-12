@echo off
setlocal EnableExtensions
set OUT=C:\ctfir-test\out-ad-server
if exist "%OUT%" rmdir /s /q "%OUT%"
mkdir "%OUT%"
C:\ctfir-test\ctfir.exe scan --out "%OUT%" --profile full > C:\ctfir-test\out-ad-server-stdout.txt 2> C:\ctfir-test\out-ad-server-stderr.txt
echo EXIT=%ERRORLEVEL%
echo stdout C:\ctfir-test\out-ad-server-stdout.txt
echo stderr C:\ctfir-test\out-ad-server-stderr.txt
exit /b %ERRORLEVEL%
