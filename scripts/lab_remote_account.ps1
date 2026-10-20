# One-time account for isolated lab remoting. Run inside each VM as Administrator.
# Use -Remove after testing. No passwords are stored in this script or its output.
#Requires -RunAsAdministrator
[CmdletBinding()]
param([switch]$Remove)

$ErrorActionPreference = 'Stop'
$account = 'vmboxlab'
$existing = Get-LocalUser -Name $account -ErrorAction SilentlyContinue
if ($Remove) {
    if ($null -ne $existing) {
        Remove-LocalUser -Name $account
        Write-Output "removed local lab account: $env:COMPUTERNAME\$account"
    }
    else {
        Write-Output 'local lab account already absent'
    }
    return
}
if ($null -ne $existing) {
    throw 'Local lab account already exists; refusing to reset or reuse it.'
}
$remotePolicy = Get-ItemPropertyValue `
    -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' `
    -Name LocalAccountTokenFilterPolicy -ErrorAction SilentlyContinue
if ($remotePolicy -ne 1) {
    throw 'PowerShell remoting local-account policy is not enabled on this VM.'
}
$password = Read-Host "Choose a strong password for $env:COMPUTERNAME\$account" -AsSecureString
$expires = (Get-Date).AddDays(14)
New-LocalUser -Name $account -Password $password -AccountExpires $expires `
    -Description 'Temporary V-MBOX lab remote account' | Out-Null
try {
    Add-LocalGroupMember -Group Administrators -Member $account
}
catch {
    Remove-LocalUser -Name $account
    throw
}
Write-Output "created: $env:COMPUTERNAME\$account"
Write-Output "expires: $($expires.ToString('o'))"
Write-Output 'Remove after testing: .\scripts\lab_remote_account.ps1 -Remove'
