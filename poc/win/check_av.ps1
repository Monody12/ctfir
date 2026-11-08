Write-Output "== AV products =="
Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct |
    Select-Object displayName, productState | Format-Table -AutoSize

Write-Output "== Defender operational events (detection/remediation) =="
Get-WinEvent -LogName 'Microsoft-Windows-Windows Defender/Operational' -MaxEvents 40 -ErrorAction SilentlyContinue |
    Where-Object { $_.Id -in 1116,1117,1118,1119,1160,1161 } |
    Select-Object -First 6 TimeCreated, Id, @{n='Info';e={($_.Message -split "`r?`n")[0..4] -join ' | '}} |
    Format-List
