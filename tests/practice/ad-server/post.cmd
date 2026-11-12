@echo off
setlocal EnableExtensions
echo ---- SMBSIGN after fix ----
findstr /c:"WIN.AD.SMBSIGN.001" C:\ctfir-test\out-ad-fix\findings.json
if errorlevel 1 (echo GONE SMBSIGN) else echo STILL SMBSIGN
echo ---- Spooler ----
sc query Spooler
sc qc Spooler
echo ---- SYSVOL leftover ----
if exist C:\Windows\SYSVOL (echo SYSVOL STILL THERE) else echo SYSVOL gone
echo ---- ntds leftover ----
if exist C:\Windows\Temp\ntds.dit (echo ntds.dit STILL) else echo ntds.dit gone
if exist C:\Windows\Temp\ctfir-marker-ntds.dit (echo marker-ntds STILL) else echo marker-ntds gone
echo POST_DONE
exit /b 0
