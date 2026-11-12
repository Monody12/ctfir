@echo off
setlocal EnableExtensions
rem JW2026-WIN7-01 cleanup. Only ctfir-marker objects + Guest/UAC/blankpwd reversions from this set.
rem Leaves A7C9, sshd, Administrator, VMware, event logs, sethc.exe untouched.

set STATEDIR=C:\ctfir-test\jw2026-win7-01
set LOG=%STATEDIR%\cleanup.log
set TEMPDIR=C:\Windows\Temp
if not exist "%STATEDIR%" mkdir "%STATEDIR%"
echo [%DATE% %TIME%] cleanup start > "%LOG%"

net user ctfir-marker$ /delete >> "%LOG%" 2>&1
net localgroup Administrators Guest /delete >> "%LOG%" 2>&1
net user Guest /active:no >> "%LOG%" 2>&1

reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList" /v "ctfir-marker$" /f >> "%LOG%" 2>&1
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v ctfir-marker /f >> "%LOG%" 2>&1
schtasks /delete /tn ctfir-marker-sync /f >> "%LOG%" 2>&1
sc stop ctfir-marker-WinUpdate >> "%LOG%" 2>&1
sc delete ctfir-marker-WinUpdate >> "%LOG%" 2>&1
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ctfir-marker-ifeo.exe" /f >> "%LOG%" 2>&1
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v UserInitMprLogonScript /f >> "%LOG%" 2>&1

rem hosts: drop only this set's line, keep A7C9
set HOSTS=%SystemRoot%\System32\drivers\etc\hosts
set HOSTSTMP=%TEMPDIR%\ctfir-marker-hosts.tmp
findstr /v /c:"ctfir-marker.jtt.local" "%HOSTS%" > "%HOSTSTMP%"
findstr /c:"Microsoft" "%HOSTSTMP%" >nul 2>&1
if not errorlevel 1 copy /y "%HOSTSTMP%" "%HOSTS%" >nul
del /f /q "%HOSTSTMP%" >nul 2>&1

netsh interface portproxy delete v4tov4 listenport=13389 listenaddress=0.0.0.0 >> "%LOG%" 2>&1
net share ctfir-marker /delete >> "%LOG%" 2>&1

del /f /q "%TEMPDIR%\ctfir-marker-sync.bat" >> "%LOG%" 2>&1
del /f /q "%TEMPDIR%\ctfir-marker-svc.exe" >> "%LOG%" 2>&1
del /f /q "%TEMPDIR%\ctfir-marker-drop.exe" >> "%LOG%" 2>&1
del /f /q "%TEMPDIR%\ctfir-marker-logon.bat" >> "%LOG%" 2>&1
del /f /q "%TEMPDIR%\ctfir-marker-u.exe" >> "%LOG%" 2>&1
rmdir /s /q "%TEMPDIR%\ctfir-marker-share" >> "%LOG%" 2>&1
del /f /q "%USERPROFILE%\Desktop\ctfir-marker-report.pdf.exe" >> "%LOG%" 2>&1
del /f /q "%USERPROFILE%\Desktop\ctfir-marker-note.txt" >> "%LOG%" 2>&1
del /f /q "%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\ctfir-marker.vbs" >> "%LOG%" 2>&1

reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f >> "%LOG%" 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LimitBlankPasswordUse /t REG_DWORD /d 1 /f >> "%LOG%" 2>&1

echo CLEANED JW2026-WIN7-01
echo log %LOG%
exit /b 0
