@echo off
setlocal EnableExtensions
echo ==== SYSVOL tree ====
dir /s /b C:\Windows\SYSVOL 2>nul
echo ==== Temp ntds ====
dir /s /b C:\Windows\Temp\ctfir-marker* 2>nul
dir /s /b C:\Windows\Temp\*ntds* 2>nul
echo ==== GptTmpl ====
if exist "C:\Windows\SYSVOL\sysvol\ctfir.local\Policies\{00000000-0000-0000-0000-00000000C0DE}\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf" (
  echo EXISTS GptTmpl.inf
  type "C:\Windows\SYSVOL\sysvol\ctfir.local\Policies\{00000000-0000-0000-0000-00000000C0DE}\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf"
) else (
  echo MISSING GptTmpl.inf
)
echo ==== install.log tail ====
type C:\ctfir-test\ad-server-01\install.log
echo ==== findings DELEG/NTDS/gptmpl ====
findstr /i "DELEG NTDS gptmpl ntds GPO.DELEG NTDS.COPY" C:\ctfir-test\out-ad-server\findings.json
echo ==== module FILES ====
if exist C:\ctfir-test\out-ad-server\modules.json findstr /i "WIN.AD.FILES finding_ids ntds GptTmpl 500" C:\ctfir-test\out-ad-server\modules.json
echo ==== session ====
if exist C:\ctfir-test\out-ad-server\session.json type C:\ctfir-test\out-ad-server\session.json
echo ==== orig flags ====
dir /b C:\ctfir-test\ad-server-01\orig
echo DIAG_DONE
exit /b 0
