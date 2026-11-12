@echo off
echo ====USER====
net user ctfir-marker$
echo ====ADMINS====
net localgroup Administrators
echo ====GUEST====
net user Guest | findstr /i "active Account"
echo ====USERLIST====
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList"
echo ====RUN====
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v ctfir-marker
echo ====TASK====
schtasks /query /tn ctfir-marker-sync /fo LIST /v
echo ====SVC====
sc qc ctfir-marker-WinUpdate
echo ====IFEO====
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ctfir-marker-ifeo.exe"
echo ====LOGONSCRIPT====
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v UserInitMprLogonScript
echo ====HOSTS====
findstr /c:"ctfir-marker" C:\Windows\System32\drivers\etc\hosts
echo ====PORTPROXY====
netsh interface portproxy show all
echo ====SHARE====
net share
echo ====UAC====
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA
echo ====BLANK====
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LimitBlankPasswordUse
echo ====FILES====
dir /b C:\Windows\Temp\ctfir-marker*
dir /b %USERPROFILE%\Desktop\ctfir-marker*
dir /r %USERPROFILE%\Desktop\ctfir-marker-note.txt
dir /b "%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\ctfir-marker*"
echo ====DONE====
