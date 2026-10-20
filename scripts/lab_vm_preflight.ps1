# Read-only two-VM preflight. Run on the laptop in Windows PowerShell.
# Credentials exist only in this process; they are never written to the log.
[CmdletBinding()]
param(
    [string]$MonitoredAddress = '192.168.189.128',
    [string]$AnchorAddress = '192.168.189.129',
    [string]$MonitoredName = 'ajjj',
    [string]$AnchorName = 'VMBOX-ANCHOR',
    [string]$UserName = 'aatmi',
    [string]$RepoPath = 'C:\Users\aatmi\OneDrive\Desktop\vmbox'
)

$ErrorActionPreference = 'Stop'
if ($MonitoredAddress -eq $AnchorAddress) {
    throw 'The monitored and anchor addresses must differ.'
}

$monitoredCredential = Get-Credential -UserName "$MonitoredName\$UserName" -Message 'Monitored VM password'
$anchorCredential = Get-Credential -UserName "$AnchorName\$UserName" -Message 'Anchor VM password'
if ($null -eq $monitoredCredential -or $null -eq $anchorCredential) {
    throw 'Credential prompt cancelled.'
}

$sessions = @()
try {
    $monitoredSession = New-PSSession -ComputerName $MonitoredAddress -Credential $monitoredCredential -Authentication Negotiate
    $sessions += $monitoredSession
    $anchorSession = New-PSSession -ComputerName $AnchorAddress -Credential $anchorCredential -Authentication Negotiate
    $sessions += $anchorSession

    $inspect = {
        param([string]$Checkout)
        $python = Get-Command python -ErrorAction SilentlyContinue
        $sysmon = Get-Command sysmon64.exe -ErrorAction SilentlyContinue
        $commit = $null
        $dirty = $null
        if (Test-Path -LiteralPath (Join-Path $Checkout '.git')) {
            $commit = (& git -C $Checkout rev-parse HEAD 2>$null | Select-Object -First 1)
            $dirty = (@(& git -C $Checkout status --porcelain 2>$null).Count -ne 0)
        }
        [PSCustomObject]@{
            host = $env:COMPUTERNAME
            ipv4 = @(Get-NetIPAddress -AddressFamily IPv4 |
                Where-Object { $_.IPAddress -notlike '169.254.*' -and $_.IPAddress -ne '127.0.0.1' } |
                Select-Object -ExpandProperty IPAddress)
            account = (whoami)
            repo_present = (Test-Path -LiteralPath (Join-Path $Checkout '.git'))
            git_commit = $commit
            git_dirty = $dirty
            python = if ($null -eq $python) { $null } else { (& python --version 2>&1 | Select-Object -First 1).ToString() }
            sysmon_version = if ($null -eq $sysmon) { $null } else { (Get-Item $sysmon.Source).VersionInfo.ProductVersion }
            winrm = (Get-Service WinRM).Status.ToString()
        }
    }

    $monitored = Invoke-Command -Session $monitoredSession -ScriptBlock $inspect -ArgumentList $RepoPath
    $anchor = Invoke-Command -Session $anchorSession -ScriptBlock $inspect -ArgumentList $RepoPath
    if ($monitored.host -ne $MonitoredName -or $anchor.host -ne $AnchorName) {
        throw 'Remote host identity does not match the expected VM names.'
    }
    $summary = [PSCustomObject]@{
        monitored = $monitored
        anchor = $anchor
        same_git_commit = ($monitored.git_commit -eq $anchor.git_commit)
        note = 'Read-only preflight; live capture and anchor behavior not tested yet.'
    }
    $summary | ConvertTo-Json -Depth 6
}
finally {
    if ($sessions.Count) { Remove-PSSession -Session $sessions }
}
