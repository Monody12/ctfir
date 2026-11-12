@echo off
setlocal EnableExtensions
for /r C:\Windows\SYSVOL %%F in (GptTmpl.inf) do (
  echo FILE=%%F
  certutil -encodehex "%%F" C:\ctfir-test\ad-server-01\gptmpl.hex
)
echo ---- hex ----
type C:\ctfir-test\ad-server-01\gptmpl.hex
echo ---- ntds copy ----
certutil -encodehex "C:\Windows\Temp\ctfir-marker-ntds.dit" C:\ctfir-test\ad-server-01\ntds.hex
type C:\ctfir-test\ad-server-01\ntds.hex
echo HEX_DONE
exit /b 0
