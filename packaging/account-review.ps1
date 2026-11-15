# Read-only account review. Compatible with Windows PowerShell 5.1; no AD module needed.
[CmdletBinding()]
param([ValidatePattern('^[\p{L}\p{N}_][\p{L}\p{N}_. @-]{0,63}\$?$')][string]$Name, [switch]$Dependencies)
Set-StrictMode -Version 2.0
function Get-AccountRolePolicy {
    param([string]$ProductType)
    if ($ProductType -eq 'LanmanNT') { return 'SkipLocalSAM_DomainController' }
    if ($ProductType -in @('WinNT','ServerNT')) { return 'LocalSAMOnly' }
    return 'SkipLocalSAM_UnknownRole'
}
function Get-AccountIdentityFacts {
    param([string]$Sid,[string]$AccountName,[bool]$LocalAccount)
    $rid = $null
    if ($Sid -match '^S-1-5-21-\d+-\d+-\d+-(\d+)$') { $rid = [uint32]$Matches[1] }
    [pscustomobject]@{Name=$AccountName; SID=$Sid; RID=$rid; LocalAccount=$LocalAccount;
        ProtectedBuiltinAdministrator=($rid -eq 500); BuiltinGuest=($rid -eq 501);
        Scope=$(if($LocalAccount){'LocalSAM'}else{'NotLocalSAM_DoNotManageHere'});
        MaliciousByNameOrPrivilege=$false; AutomaticModificationAllowed=$false}
}
function Get-BuiltinAdminGroupSid { return 'S-1-5-32-544' }
if ($MyInvocation.InvocationName -eq '.') { return }
$ErrorActionPreference='Stop'
try {
    $product=(Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\ProductOptions' -Name ProductType).ProductType
    $policy=Get-AccountRolePolicy $product
    Write-Output ('ROLE ProductType='+$product+' policy='+$policy+' PowerShell='+$PSVersionTable.PSVersion+' Is64BitProcess='+[Environment]::Is64BitProcess)
    if($policy -ne 'LocalSAMOnly') { Write-Warning 'Local SAM is not available or role is unknown. No AD/domain or account query performed.'; exit 3 }
    $users=$null
    try { $users=@(Get-CimInstance -ClassName Win32_UserAccount -Filter 'LocalAccount=True' -ErrorAction Stop) }
    catch { try { $users=@(Get-WmiObject -Class Win32_UserAccount -Filter 'LocalAccount=True' -ErrorAction Stop) } catch { $users=$null } }
    if($null -eq $users) {
        if($Name) {
            Write-Warning 'CIM/WMI account SID unavailable; local net query only. Output is insufficient to authorize deletion.'
            & "$env:SystemRoot\System32\net.exe" user $Name
        } else { Write-Warning 'CIM/WMI unavailable. No SID-verified account inventory.' }
        exit 3
    }
    if($Name) { $users=@($users | Where-Object {$_.Name -eq $Name}) }
    if($Name -and $users.Count -ne 1) { Write-Warning 'Expected exactly one local SAM name. Not found or ambiguous; stop.'; exit 3 }
    foreach($u in $users) { Get-AccountIdentityFacts -Sid $u.SID -AccountName $u.Name -LocalAccount ([bool]$u.LocalAccount) | Format-List }
    # Fixed well-known SID, never an English/localized group name and no remote member resolution.
    Get-CimInstance -ClassName Win32_Group -Filter "LocalAccount=True AND SID='S-1-5-32-544'" -ErrorAction SilentlyContinue | Select-Object Name,SID,LocalAccount
    if($Dependencies -and $Name -and $users.Count -eq 1) {
        $identities=@($Name,('.\'+$Name),($env:COMPUTERNAME+'\'+$Name),$users[0].SID)
        Write-Output 'DEPENDENCY REVIEW ONLY: service StartName / scheduled-task Principal; not a removal plan.'
        Get-CimInstance -ClassName Win32_Service | Where-Object {$_.StartName -in $identities} | Select-Object Name,StartName,State
        if(Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue) {
            Get-ScheduledTask | Where-Object {$_.Principal.UserId -in $identities} | Select-Object TaskPath,TaskName,@{n='Principal';e={$_.Principal.UserId}}
        } else { Write-Warning 'ScheduledTasks module missing; task principal dependency coverage incomplete.' }
        Write-Output 'Inspect current local logon sessions separately. Group principals, aliases and indirect dependencies require human review.'
    }
    Write-Output 'PREVIEW ONLY. Preserve an independent administrator, evidence and profiles. SID/RID and approval must be rechecked before every manual change.'
    exit 0
} catch { Write-Error ('Read-only review incomplete: '+$_.Exception.Message); exit 3 }
