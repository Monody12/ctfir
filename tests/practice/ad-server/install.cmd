@echo off
setlocal EnableExtensions
rem AD/Server fixture for Win7 analog tests. Prefix ctfir-marker.
rem Does NOT touch JW2026, Administrator password, sshd, sethc, Spooler start type, firewall.
rem Re-run keeps existing orig\*.flag (does not overwrite first backup).

set SRC=%~dp0
if "%SRC:~-1%"=="\" set SRC=%SRC:~0,-1%
set STATE=C:\ctfir-test\ad-server-01
set LOG=%STATE%\install.log
set WIN=%SystemRoot%
set GPO={00000000-0000-0000-0000-00000000C0DE}
set SYSVOL=%WIN%\SYSVOL\sysvol\ctfir.local
set POL=%SYSVOL%\Policies\%GPO%

if not exist "%STATE%" mkdir "%STATE%"
if not exist "%STATE%\orig" mkdir "%STATE%\orig"
echo [%DATE% %TIME%] plant start > "%LOG%"

call :backup_dw "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" LmCompatibilityLevel lmcompat
call :backup_dw "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" NoLmHash nolmhash
call :backup_dw "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" RestrictAnonymousSAM restrictsam
call :backup_dw "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" EveryoneIncludesAnonymous everyoneanon
call :backup_dw "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" DsrmAdminLogonBehavior dsrm
call :backup_dw "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" UseLogonCredential wdigest
call :backup_dw "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" LocalAccountTokenFilterPolicy latfp
call :backup_dw "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" LDAPServerIntegrity ldap
call :backup_dw "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" EnablePlainTextPassword plainsmb
call :backup_dw "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" NoWarningNoElevationOnInstall pnp
call :backup_dw "HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer" AlwaysInstallElevated aie
call :backup_dw "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" AllowUnencrypted winrmu
call :backup_dw "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" AllowBasic winrmb
call :backup_dw "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" DisablePasswordChange machpwd
call :backup_dw "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" SealSecureChannel sealchan
call :backup_dw "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" RequireSignOrSeal signseal
call :backup_dw "HKLM\SYSTEM\CurrentControlSet\Services\LDAP" LDAPClientIntegrity ldapcli
call :backup_dw "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" LdapEnforceChannelBinding ldapbind
call :backup_dw "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" ConsentPromptBehaviorAdmin uacnp
call :backup_dw "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" DisableCAD cad
call :backup_dw "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" RestrictDriverInstallationToAdministrators pnpadm
call :backup_dw "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" SecurityLayer rdpsl
call :backup_any "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" CachedLogonsCount cachedlog
call :backup_dw "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" enableforcedlogoff forcelog
call :backup_dw "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" NtlmMinClientSec ntlmsec
call :backup_any "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell" ExecutionPolicy psexec
call :backup_dw "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" AllowUnencrypted winrmc
call :backup_dw "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" MinEncryptionLevel rdpenc
call :backup_dw "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" ForceGuest forcegst
call :backup_dw "HKLM\SYSTEM\CurrentControlSet\Services\RemoteRegistry" Start remotreg

mkdir "%POL%\Machine\Preferences\Groups" >nul 2>&1
mkdir "%POL%\Machine\Preferences\ScheduledTasks" >nul 2>&1
mkdir "%POL%\Machine\Preferences\Registry" >nul 2>&1
mkdir "%POL%\Machine\Preferences\Files" >nul 2>&1
mkdir "%POL%\Machine\Preferences\Services" >nul 2>&1
mkdir "%POL%\Machine\Scripts" >nul 2>&1
mkdir "%POL%\MACHINE\Microsoft\Windows NT\SecEdit" >nul 2>&1
mkdir "%SYSVOL%\scripts" >nul 2>&1
mkdir "%WIN%\Temp\ctfir-marker-ifm\Active Directory" >nul 2>&1
mkdir "%WIN%\Temp\ctfir-marker-ifm\registry" >nul 2>&1

copy /y "%SRC%\Groups.xml" "%POL%\Machine\Preferences\Groups\Groups.xml" >> "%LOG%" 2>&1
copy /y "%SRC%\ScheduledTasks.xml" "%POL%\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml" >> "%LOG%" 2>&1
copy /y "%SRC%\Registry.xml" "%POL%\Machine\Preferences\Registry\Registry.xml" >> "%LOG%" 2>&1
copy /y "%SRC%\Files.xml" "%POL%\Machine\Preferences\Files\Files.xml" >> "%LOG%" 2>&1
copy /y "%SRC%\Services.xml" "%POL%\Machine\Preferences\Services\Services.xml" >> "%LOG%" 2>&1
copy /y "%SRC%\scripts.ini" "%POL%\Machine\Scripts\scripts.ini" >> "%LOG%" 2>&1
copy /y "%SRC%\GptTmpl.inf" "%POL%\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf" >> "%LOG%" 2>&1
copy /y "%SRC%\ctfir-marker.bat" "%SYSVOL%\scripts\ctfir-marker.bat" >> "%LOG%" 2>&1
copy /y "%SRC%\ntds.dit" "%WIN%\Temp\ctfir-marker-ntds.dit" >> "%LOG%" 2>&1
copy /y "%SRC%\ntds.dit" "%WIN%\Temp\ntds.dit" >> "%LOG%" 2>&1
copy /y "%SRC%\ntds.dit" "%WIN%\Temp\ctfir-marker-ifm\Active Directory\ntds.dit" >> "%LOG%" 2>&1
echo ctfir-marker-SYSTEM-hive-dummy> "%WIN%\Temp\ctfir-marker-ifm\registry\SYSTEM"
echo ctfir-marker-sam-dummy> "%WIN%\Temp\sam.save"
echo ctfir-marker-system-dummy> "%WIN%\Temp\system.save"
echo ctfir-marker-lsass-dummy> "%WIN%\Temp\lsass.dmp"
echo rem ctfir-marker gpo> "%WIN%\Temp\ctfir-marker-gpo.bat"

reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v DsrmAdminLogonBehavior /t REG_DWORD /d 2 /f >> "%LOG%" 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" /v LDAPServerIntegrity /t REG_DWORD /d 0 /f >> "%LOG%" 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential /t REG_DWORD /d 1 /f >> "%LOG%" 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LmCompatibilityLevel /t REG_DWORD /d 1 /f >> "%LOG%" 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f >> "%LOG%" 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v NoLmHash /t REG_DWORD /d 0 /f >> "%LOG%" 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictAnonymousSAM /t REG_DWORD /d 0 /f >> "%LOG%" 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v EveryoneIncludesAnonymous /t REG_DWORD /d 1 /f >> "%LOG%" 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v EnablePlainTextPassword /t REG_DWORD /d 1 /f >> "%LOG%" 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" /v NoWarningNoElevationOnInstall /t REG_DWORD /d 1 /f >> "%LOG%" 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer" /v AlwaysInstallElevated /t REG_DWORD /d 1 /f >> "%LOG%" 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" /v AllowUnencrypted /t REG_DWORD /d 1 /f >> "%LOG%" 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" /v AllowBasic /t REG_DWORD /d 1 /f >> "%LOG%" 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" /v AllowUnencrypted /t REG_DWORD /d 1 /f >> "%LOG%" 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v DisablePasswordChange /t REG_DWORD /d 1 /f >> "%LOG%" 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v SealSecureChannel /t REG_DWORD /d 0 /f >> "%LOG%" 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v RequireSignOrSeal /t REG_DWORD /d 0 /f >> "%LOG%" 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LDAP" /v LDAPClientIntegrity /t REG_DWORD /d 0 /f >> "%LOG%" 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" /v LdapEnforceChannelBinding /t REG_DWORD /d 0 /f >> "%LOG%" 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 0 /f >> "%LOG%" 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v DisableCAD /t REG_DWORD /d 1 /f >> "%LOG%" 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" /v RestrictDriverInstallationToAdministrators /t REG_DWORD /d 0 /f >> "%LOG%" 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f >> "%LOG%" 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v CachedLogonsCount /t REG_SZ /d 50 /f >> "%LOG%" 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v enableforcedlogoff /t REG_DWORD /d 0 /f >> "%LOG%" 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" /v NtlmMinClientSec /t REG_DWORD /d 0 /f >> "%LOG%" 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell" /v ExecutionPolicy /t REG_SZ /d Unrestricted /f >> "%LOG%" 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v MinEncryptionLevel /t REG_DWORD /d 1 /f >> "%LOG%" 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v ForceGuest /t REG_DWORD /d 1 /f >> "%LOG%" 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\RemoteRegistry" /v Start /t REG_DWORD /d 2 /f >> "%LOG%" 2>&1

echo PLANTED AD-SERVER-01>> "%LOG%"
echo PLANTED AD-SERVER-01
echo log %LOG%
exit /b 0

:backup_dw
if exist "%STATE%\orig\%3.flag" goto :eof
reg query %1 /v %2 > "%STATE%\orig\%3.txt" 2>&1
if errorlevel 1 (
  echo MISSING> "%STATE%\orig\%3.flag"
) else (
  echo PRESENT> "%STATE%\orig\%3.flag"
)
goto :eof

:backup_any
if exist "%STATE%\orig\%3.flag" goto :eof
reg query %1 /v %2 > "%STATE%\orig\%3.txt" 2>&1
if errorlevel 1 (
  echo MISSING> "%STATE%\orig\%3.flag"
) else (
  echo PRESENT> "%STATE%\orig\%3.flag"
)
goto :eof
