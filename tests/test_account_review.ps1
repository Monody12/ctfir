$ErrorActionPreference='Stop'
. "$PSScriptRoot\..\packaging\account-review.ps1"
$count=0
function Assert-Safe($Condition,[string]$Label) { $script:count++; if(-not $Condition) {throw $Label} }
Assert-Safe ((Get-AccountRolePolicy 'LanmanNT') -eq 'SkipLocalSAM_DomainController') 'DC must skip local SAM'
Assert-Safe ((Get-AccountRolePolicy '') -eq 'SkipLocalSAM_UnknownRole') 'Unknown role fail closed'
foreach($role in @('WinNT','ServerNT')) {Assert-Safe ((Get-AccountRolePolicy $role) -eq 'LocalSAMOnly') 'Local role'}
foreach($name in @('Administrator','renamed-built-in','renamed$','管理员')) {
 $f=Get-AccountIdentityFacts -Sid 'S-1-5-21-1-2-3-500' -AccountName $name -LocalAccount $true
 Assert-Safe $f.ProtectedBuiltinAdministrator 'RID500 protected independent of name'
 Assert-Safe (-not $f.MaliciousByNameOrPrivilege) 'No name-based malicious verdict'
 Assert-Safe (-not $f.AutomaticModificationAllowed) 'No mutation'
}
foreach($label in @('Administrators','Administrateurs','管理员')) {Assert-Safe ((Get-BuiltinAdminGroupSid) -eq 'S-1-5-32-544') ('Group language independent '+$label)}
$f=Get-AccountIdentityFacts -Sid 'S-1-5-21-1-2-3-1000' -AccountName 'legitimate-backup-service' -LocalAccount $true
Assert-Safe (-not $f.ProtectedBuiltinAdministrator) 'RID1000 custom account'
Assert-Safe (-not $f.MaliciousByNameOrPrivilege) 'Legitimate service is not intrusion by privilege'
$f=Get-AccountIdentityFacts -Sid 'S-1-5-21-9-8-7-1500' -AccountName 'domain-ops' -LocalAccount $false
Assert-Safe ($f.Scope -eq 'NotLocalSAM_DoNotManageHere') 'Domain account never local deletion'
$tokens=$null;$errors=$null
[void][System.Management.Automation.Language.Parser]::ParseFile("$PSScriptRoot\..\packaging\account-review.ps1",[ref]$tokens,[ref]$errors)
Assert-Safe ($errors.Count -eq 0) 'PS5.1 syntax'
$os=Get-CimInstance Win32_OperatingSystem
Write-Output ('ACTUAL_CI_OS='+$os.Caption+' VERSION='+$os.Version+' PS='+$PSVersionTable.PSVersion)
Write-Output ('ACCOUNT_PREVIEW checks='+$count+' failures=0')
