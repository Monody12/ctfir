@echo off
setlocal EnableExtensions
echo ---- cleanup.log ----
type C:\ctfir-test\ad-server-01\cleanup.log
echo ---- sample regs ----
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LmCompatibilityLevel
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v NoLmHash
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictAnonymousSAM
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v DsrmAdminLogonBehavior
reg query "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v CachedLogonsCount
echo ---- orig flags sample ----
type C:\ctfir-test\ad-server-01\orig\lmcompat.flag
type C:\ctfir-test\ad-server-01\orig\lmcompat.txt
echo ---- Spooler ----
sc query Spooler | findstr STATE
echo CHECK_DONE
exit /b 0
