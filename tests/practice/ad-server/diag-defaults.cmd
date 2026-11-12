@echo off
setlocal EnableExtensions
echo ====VER====
ver
echo ====MinEncryptionLevel====
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v MinEncryptionLevel
echo ====RemoteRegistry====
sc qc RemoteRegistry
reg query "HKLM\SYSTEM\CurrentControlSet\Services\RemoteRegistry" /v Start
echo ====ForceGuest====
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v ForceGuest
echo ====Netlogon====
reg query "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v DisablePasswordChange
reg query "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v SealSecureChannel
echo ====SYSVOL====
if exist %SystemRoot%\SYSVOL (echo SYSVOL_PRESENT) else echo SYSVOL_ABSENT
echo ====ntds copies====
if exist %SystemRoot%\Temp\ntds.dit (echo NTDS_TEMP_PRESENT) else echo NTDS_TEMP_ABSENT
if exist %SystemRoot%\Temp\sam.save (echo SAM_SAVE_PRESENT) else echo SAM_SAVE_ABSENT
echo ====Spooler====
sc qc Spooler
echo ====JW Guest====
net localgroup Administrators
echo ====ctfir====
C:\ctfir-test\ctfir.exe doctor
exit /b 0
