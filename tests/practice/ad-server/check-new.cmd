@echo off
setlocal EnableExtensions
echo ====MinEnc====
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v MinEncryptionLevel
echo ====ForceGuest====
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v ForceGuest
echo ====RemoteReg====
sc qc RemoteRegistry
echo ====files====
if exist %SystemRoot%\SYSVOL (echo SYSVOL_PRESENT) else echo SYSVOL_ABSENT
if exist %SystemRoot%\Temp\sam.save (echo SAM_SAVE_PRESENT) else echo SAM_SAVE_ABSENT
if exist %SystemRoot%\Temp\lsass.dmp (echo LSASS_PRESENT) else echo LSASS_ABSENT
if exist %SystemRoot%\Temp\ntds.dit (echo NTDS_PRESENT) else echo NTDS_ABSENT
echo ====planted IDs in clean scan====
set F=C:\ctfir-test\out-ad-clean\findings.json
for %%R in (WIN.AD.HIVE.COPY.001 WIN.AD.LSASS.DMP.001 WIN.AD.GPP.FILE.001 WIN.AD.GPP.SVC.001 WIN.BASE.RDP.ENCRYPT.001 WIN.BASE.REMOTEREG.001 WIN.BASE.FORCEGUEST.001 WIN.AD.GPP.CPASSWORD.001 WIN.AD.NTDS.COPY.001 WIN.AD.SPOOLER.DC.001) do (
  findstr /c:"%%R" "%F%" >nul
  if errorlevel 1 (echo GONE %%R) else echo STILL %%R
)
echo ====JW====
findstr /c:"WIN.ACC.GUESTADMIN.001" "%F%" >nul
if errorlevel 1 (echo MISS JW GuestAdmin) else echo HIT  JW GuestAdmin
findstr /c:"WIN.AUTORUN.IFEO.001" "%F%" >nul
if errorlevel 1 (echo MISS JW IFEO) else echo HIT  JW IFEO
echo ====lab original====
findstr /c:"WIN.AD.MACHPWD.001" "%F%" >nul
if errorlevel 1 (echo GONE MACHPWD) else echo STILL MACHPWD lab-original
findstr /c:"WIN.BASE.SEALCHAN.001" "%F%" >nul
if errorlevel 1 (echo GONE SEALCHAN) else echo STILL SEALCHAN lab-original
echo CHECK_NEW_DONE
exit /b 0
