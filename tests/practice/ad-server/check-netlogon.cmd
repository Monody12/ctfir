@echo off
echo ---- netlogon ----
reg query "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v DisablePasswordChange
reg query "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v SealSecureChannel
reg query "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v RequireSignOrSeal
echo ---- orig machpwd ----
echo FLAG:
type C:\ctfir-test\ad-server-01\orig\machpwd.flag
echo TXT:
type C:\ctfir-test\ad-server-01\orig\machpwd.txt
echo ---- orig sealchan ----
echo FLAG:
type C:\ctfir-test\ad-server-01\orig\sealchan.flag
echo TXT:
type C:\ctfir-test\ad-server-01\orig\sealchan.txt
echo ---- orig signseal ----
echo FLAG:
type C:\ctfir-test\ad-server-01\orig\signseal.flag
echo TXT:
type C:\ctfir-test\ad-server-01\orig\signseal.txt
echo ---- findings ----
findstr /c:"WIN.AD.MACHPWD" /c:"WIN.BASE.SEALCHAN" C:\ctfir-test\out-ad-clean\findings.json
echo NETLOGON_DONE
exit /b 0
