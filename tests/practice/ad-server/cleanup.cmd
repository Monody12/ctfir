@echo off
setlocal EnableExtensions
rem Restore AD/Server fixtures. Does NOT touch JW2026, Spooler, firewall, EnableLUA, LimitBlankPasswordUse.

set STATE=C:\ctfir-test\ad-server-01
set LOG=%STATE%\cleanup.log
set WIN=%SystemRoot%

echo [%DATE% %TIME%] cleanup start > "%LOG%"

call :rst_dw "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" LmCompatibilityLevel lmcompat
call :rst_dw "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" NoLmHash nolmhash
call :rst_dw "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" RestrictAnonymousSAM restrictsam
call :rst_dw "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" EveryoneIncludesAnonymous everyoneanon
call :rst_dw "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" DsrmAdminLogonBehavior dsrm
call :rst_dw "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" UseLogonCredential wdigest
call :rst_dw "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" LocalAccountTokenFilterPolicy latfp
call :rst_dw "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" LDAPServerIntegrity ldap
call :rst_dw "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" EnablePlainTextPassword plainsmb
call :rst_dw "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" NoWarningNoElevationOnInstall pnp
call :rst_dw "HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer" AlwaysInstallElevated aie
call :rst_dw "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" AllowUnencrypted winrmu
call :rst_dw "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" AllowBasic winrmb
call :rst_dw "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" AllowUnencrypted winrmc
call :rst_dw "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" DisablePasswordChange machpwd
call :rst_dw "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" SealSecureChannel sealchan
call :rst_dw "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" RequireSignOrSeal signseal
call :rst_dw "HKLM\SYSTEM\CurrentControlSet\Services\LDAP" LDAPClientIntegrity ldapcli
call :rst_dw "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" LdapEnforceChannelBinding ldapbind
call :rst_dw "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" ConsentPromptBehaviorAdmin uacnp
call :rst_dw "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" DisableCAD cad
call :rst_dw "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" RestrictDriverInstallationToAdministrators pnpadm
call :rst_dw "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" SecurityLayer rdpsl
call :rst_sz "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" CachedLogonsCount cachedlog
call :rst_dw "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" enableforcedlogoff forcelog
call :rst_dw "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" NtlmMinClientSec ntlmsec
call :rst_sz "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell" ExecutionPolicy psexec
call :rst_dw "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" MinEncryptionLevel rdpenc
call :rst_dw "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" ForceGuest forcegst
call :rst_dw "HKLM\SYSTEM\CurrentControlSet\Services\RemoteRegistry" Start remotreg

if exist "%WIN%\SYSVOL" rmdir /s /q "%WIN%\SYSVOL" >> "%LOG%" 2>&1
if exist "%WIN%\Temp\ctfir-marker-ifm" rmdir /s /q "%WIN%\Temp\ctfir-marker-ifm" >> "%LOG%" 2>&1
if exist "%WIN%\Temp\ctfir-marker-ntds.dit" del /f /q "%WIN%\Temp\ctfir-marker-ntds.dit" >> "%LOG%" 2>&1
if exist "%WIN%\Temp\ntds.dit" del /f /q "%WIN%\Temp\ntds.dit" >> "%LOG%" 2>&1
if exist "%WIN%\Temp\ctfir-marker-gpo.bat" del /f /q "%WIN%\Temp\ctfir-marker-gpo.bat" >> "%LOG%" 2>&1
if exist "%WIN%\Temp\sam.save" del /f /q "%WIN%\Temp\sam.save" >> "%LOG%" 2>&1
if exist "%WIN%\Temp\system.save" del /f /q "%WIN%\Temp\system.save" >> "%LOG%" 2>&1
if exist "%WIN%\Temp\lsass.dmp" del /f /q "%WIN%\Temp\lsass.dmp" >> "%LOG%" 2>&1
if exist "C:\SYSVOL" rmdir /s /q "C:\SYSVOL" >> "%LOG%" 2>&1
reg delete "HKLM\SOFTWARE\ctfir-marker" /f >> "%LOG%" 2>&1

echo CLEANED AD-SERVER-01>> "%LOG%"
echo CLEANED AD-SERVER-01
echo log %LOG%
exit /b 0

:rst_dw
if not exist "%STATE%\orig\%3.flag" (
  echo no-backup %3>> "%LOG%"
  goto :eof
)
set /p FLAG=<"%STATE%\orig\%3.flag"
if /i "%FLAG%"=="MISSING" (
  reg delete %1 /v %2 /f >> "%LOG%" 2>&1
  goto :eof
)
for /f "tokens=3" %%a in ('findstr /i "REG_DWORD" "%STATE%\orig\%3.txt"') do (
  reg add %1 /v %2 /t REG_DWORD /d %%a /f >> "%LOG%" 2>&1
)
goto :eof

:rst_sz
if not exist "%STATE%\orig\%3.flag" (
  echo no-backup %3>> "%LOG%"
  goto :eof
)
set /p FLAG=<"%STATE%\orig\%3.flag"
if /i "%FLAG%"=="MISSING" (
  reg delete %1 /v %2 /f >> "%LOG%" 2>&1
  goto :eof
)
for /f "tokens=1,2,3*" %%a in ('findstr /i "REG_" "%STATE%\orig\%3.txt"') do (
  if /i "%%b"=="REG_DWORD" (
    reg add %1 /v %2 /t REG_DWORD /d %%c /f >> "%LOG%" 2>&1
  ) else (
    reg add %1 /v %2 /t %%b /d %%c /f >> "%LOG%" 2>&1
  )
)
goto :eof
