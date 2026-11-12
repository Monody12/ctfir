@echo off
setlocal EnableExtensions
rem Contest-style fix of AD-SERVER-01 plants.
rem Does NOT disable Spooler, enable firewall, touch JW2026, EnableLUA, sshd, sethc.

set WIN=%SystemRoot%
set LOG=C:\ctfir-test\ad-server-01\fix.log
echo [%DATE% %TIME%] contest-fix start > "%LOG%"

if exist "%WIN%\SYSVOL" rmdir /s /q "%WIN%\SYSVOL" >> "%LOG%" 2>&1
if exist "%WIN%\Temp\ctfir-marker-ifm" rmdir /s /q "%WIN%\Temp\ctfir-marker-ifm" >> "%LOG%" 2>&1
if exist "%WIN%\Temp\ctfir-marker-ntds.dit" del /f /q "%WIN%\Temp\ctfir-marker-ntds.dit" >> "%LOG%" 2>&1
if exist "%WIN%\Temp\ntds.dit" del /f /q "%WIN%\Temp\ntds.dit" >> "%LOG%" 2>&1
if exist "%WIN%\Temp\ctfir-marker-gpo.bat" del /f /q "%WIN%\Temp\ctfir-marker-gpo.bat" >> "%LOG%" 2>&1
if exist "%WIN%\Temp\sam.save" del /f /q "%WIN%\Temp\sam.save" >> "%LOG%" 2>&1
if exist "%WIN%\Temp\system.save" del /f /q "%WIN%\Temp\system.save" >> "%LOG%" 2>&1
if exist "%WIN%\Temp\lsass.dmp" del /f /q "%WIN%\Temp\lsass.dmp" >> "%LOG%" 2>&1
if exist "C:\SYSVOL" rmdir /s /q "C:\SYSVOL" >> "%LOG%" 2>&1

reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v DsrmAdminLogonBehavior /t REG_DWORD /d 0 /f >> "%LOG%" 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" /v LDAPServerIntegrity /t REG_DWORD /d 2 /f >> "%LOG%" 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential /t REG_DWORD /d 0 /f >> "%LOG%" 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LmCompatibilityLevel /t REG_DWORD /d 5 /f >> "%LOG%" 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 0 /f >> "%LOG%" 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v NoLmHash /t REG_DWORD /d 1 /f >> "%LOG%" 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictAnonymousSAM /t REG_DWORD /d 1 /f >> "%LOG%" 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v EveryoneIncludesAnonymous /t REG_DWORD /d 0 /f >> "%LOG%" 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v EnablePlainTextPassword /t REG_DWORD /d 0 /f >> "%LOG%" 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" /v NoWarningNoElevationOnInstall /t REG_DWORD /d 0 /f >> "%LOG%" 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer" /v AlwaysInstallElevated /t REG_DWORD /d 0 /f >> "%LOG%" 2>&1
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer" /v AlwaysInstallElevated /t REG_DWORD /d 0 /f >> "%LOG%" 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" /v AllowUnencrypted /t REG_DWORD /d 0 /f >> "%LOG%" 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" /v AllowBasic /t REG_DWORD /d 0 /f >> "%LOG%" 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" /v AllowUnencrypted /t REG_DWORD /d 0 /f >> "%LOG%" 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v DisablePasswordChange /t REG_DWORD /d 0 /f >> "%LOG%" 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v SealSecureChannel /t REG_DWORD /d 1 /f >> "%LOG%" 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v RequireSignOrSeal /t REG_DWORD /d 1 /f >> "%LOG%" 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LDAP" /v LDAPClientIntegrity /t REG_DWORD /d 2 /f >> "%LOG%" 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" /v LdapEnforceChannelBinding /t REG_DWORD /d 2 /f >> "%LOG%" 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 5 /f >> "%LOG%" 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v DisableCAD /t REG_DWORD /d 0 /f >> "%LOG%" 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" /v RestrictDriverInstallationToAdministrators /t REG_DWORD /d 1 /f >> "%LOG%" 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 2 /f >> "%LOG%" 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v CachedLogonsCount /t REG_SZ /d 10 /f >> "%LOG%" 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v enableforcedlogoff /t REG_DWORD /d 1 /f >> "%LOG%" 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" /v NtlmMinClientSec /t REG_DWORD /d 537395200 /f >> "%LOG%" 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell" /v ExecutionPolicy /t REG_SZ /d Restricted /f >> "%LOG%" 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v MinEncryptionLevel /t REG_DWORD /d 3 /f >> "%LOG%" 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v ForceGuest /t REG_DWORD /d 0 /f >> "%LOG%" 2>&1
sc config RemoteRegistry start= disabled >> "%LOG%" 2>&1
reg delete "HKLM\SOFTWARE\ctfir-marker" /f >> "%LOG%" 2>&1

echo FIXED AD-SERVER-01>> "%LOG%"
echo FIXED AD-SERVER-01
echo log %LOG%
echo NOTE: Spooler and firewall left unchanged
exit /b 0
