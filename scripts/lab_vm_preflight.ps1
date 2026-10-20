# Read-only two-VM preflight. Run on the laptop in Windows PowerShell.
# Credentials exist only in this process; they are never written to the log.
[CmdletBinding()]
param(
    [string]$MonitoredAddress = '192.168.189.128',
    [string]$AnchorAddress = '192.168.189.129',
    [string]$MonitoredName = 'ajjj',
    [string]$AnchorName = 'VMBOX-ANCHOR',
    [string]$MonitoredUser = 'ajjj\vmboxlab',
    [string]$AnchorUser = 'VMBOX-ANCHOR\vmboxlab',
    [string]$RepoPath = 'C:\Users\aatmi\OneDrive\Desktop\vmbox'
)

$ErrorActionPreference = 'Stop'
if ($MonitoredAddress -eq $AnchorAddress) {
    throw 'The monitored and anchor addresses must differ.'
}

$monitoredCredential = Get-Credential -UserName $MonitoredUser -Message 'Monitored VM account password (not the Windows Hello PIN)'
if ($null -eq $monitoredCredential) {
    throw 'Credential prompt cancelled.'
}

$sessions = @()
try {
    $monitoredSession = New-PSSession -ComputerName $MonitoredAddress -Credential $monitoredCredential -Authentication Negotiate
    $sessions += $monitoredSession
    $anchorCredential = Get-Credential -UserName $AnchorUser -Message 'Anchor VM account password (not the Windows Hello PIN)'
    if ($null -eq $anchorCredential) {
        throw 'Credential prompt cancelled.'
    }
    $anchorSession = New-PSSession -ComputerName $AnchorAddress -Credential $anchorCredential -Authentication Negotiate
    $sessions += $anchorSession

    $inspect = {
        param([string]$Checkout)
        $pythonCandidates = @(
            (Join-Path $Checkout '.venv\Scripts\python.exe'),
            'C:\Users\aatmi\AppData\Local\Python\pythoncore-3.15-64\python.exe'
        )
        $pythonCommand = Get-Command python -ErrorAction SilentlyContinue
        if ($null -ne $pythonCommand) { $pythonCandidates += $pythonCommand.Source }
        $pythonPath = $pythonCandidates | Where-Object { Test-Path -LiteralPath $_ } |
            Select-Object -First 1
        $pythonVersion = $null
        $pythonIssue = $null
        if ($null -eq $pythonPath) {
            $pythonIssue = 'Python not found in checkout, known per-user installation, or remote account PATH'
        }
        else {
            try {
                $versionOutput = @(& $pythonPath --version 2>&1)
                if ($LASTEXITCODE -eq 0 -and $versionOutput.Count -gt 0) {
                    $pythonVersion = [string]$versionOutput[0]
                }
                else { $pythonIssue = 'Python executable exists but did not start successfully' }
            }
            catch { $pythonIssue = 'Python executable exists but could not be run by this account' }
        }
        $sysmon = Get-Command sysmon64.exe -ErrorAction SilentlyContinue
        $git = Get-Command git -ErrorAction SilentlyContinue
        if ($null -eq $git) {
            $git = Get-Command 'C:\Program Files\Git\cmd\git.exe' -ErrorAction SilentlyContinue
        }
        $commit = $null
        $dirty = $null
        $gitIssue = $null
        if ($null -eq $git) {
            $gitIssue = 'git is unavailable in remote account PATH'
        }
        elseif (Test-Path -LiteralPath (Join-Path $Checkout '.git')) {
            $rawCommit = @(& $git.Source -c "safe.directory=$Checkout" -C $Checkout rev-parse HEAD 2>&1)
            if ($LASTEXITCODE -eq 0 -and $rawCommit.Count -eq 1 -and
                $rawCommit[0] -match '^[0-9a-f]{40}$') {
                $commit = [string]$rawCommit[0]
                $rawStatus = @(& $git.Source -c "safe.directory=$Checkout" -C $Checkout status --porcelain 2>&1)
                if ($LASTEXITCODE -eq 0) {
                    $dirty = ($rawStatus.Count -ne 0)
                }
                else {
                    $gitIssue = 'git status failed'
                }
            }
            else {
                $gitIssue = 'git rev-parse failed or returned a non-commit value'
            }
        }
        else { $gitIssue = 'repository checkout missing' }
        [PSCustomObject]@{
            host = $env:COMPUTERNAME
            ipv4 = @(Get-NetIPAddress -AddressFamily IPv4 |
                Where-Object { $_.IPAddress -notlike '169.254.*' -and $_.IPAddress -ne '127.0.0.1' } |
                Select-Object -ExpandProperty IPAddress)
            account = (whoami)
            repo_present = (Test-Path -LiteralPath (Join-Path $Checkout '.git'))
            git_commit = $commit
            git_dirty = $dirty
            git_issue = $gitIssue
            python_executable = $pythonPath
            python = $pythonVersion
            python_issue = $pythonIssue
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
        same_git_commit = if ($null -eq $monitored.git_commit -or $null -eq $anchor.git_commit) {
            $null
        } else { $monitored.git_commit -eq $anchor.git_commit }
        note = 'Read-only preflight; live capture and anchor behavior not tested yet.'
    }
    $summary | ConvertTo-Json -Depth 6
}
finally {
    if ($sessions.Count) { Remove-PSSession -Session $sessions }
}
