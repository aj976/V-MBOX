# Create isolated, version-pinned checkouts and Python environments on both lab VMs.
# Run on the laptop in Windows PowerShell. Existing lab directories are never replaced.
[CmdletBinding()]
param(
    [string]$MonitoredAddress = '192.168.189.128',
    [string]$AnchorAddress = '192.168.189.129',
    [string]$MonitoredUser = 'ajjj\vmboxlab',
    [string]$AnchorUser = 'VMBOX-ANCHOR\vmboxlab',
    [string]$Python = 'C:\Users\aatmi\AppData\Local\Python\pythoncore-3.15-64\python.exe',
    [string]$GitRemote = 'https://github.com/aj976/dfirti.git'
)

$ErrorActionPreference = 'Stop'
$git = Get-Command git -ErrorAction Stop
$revision = (& $git.Source rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $revision -notmatch '^[0-9a-f]{40}$') {
    throw 'Cannot resolve the laptop checkout revision.'
}
$shortRevision = $revision.Substring(0, 8)
$runSuffix = [guid]::NewGuid().ToString('N').Substring(0, 8)
$labRoot = "C:\VmboxLab\$shortRevision-$runSuffix"

$monitoredCredential = Get-Credential -UserName $MonitoredUser -Message 'Monitored VM lab password'
if ($null -eq $monitoredCredential) { throw 'Credential prompt cancelled.' }
$sessions = @()
try {
    $monitoredSession = New-PSSession -ComputerName $MonitoredAddress -Credential $monitoredCredential -Authentication Negotiate
    $sessions += $monitoredSession
    $anchorCredential = Get-Credential -UserName $AnchorUser -Message 'Anchor VM lab password'
    if ($null -eq $anchorCredential) { throw 'Credential prompt cancelled.' }
    $anchorSession = New-PSSession -ComputerName $AnchorAddress -Credential $anchorCredential -Authentication Negotiate
    $sessions += $anchorSession

    $prepare = {
        param([string]$Root, [string]$Commit, [string]$Remote,
              [string]$BasePython, [bool]$Monitored)
        $ErrorActionPreference = 'Stop'
        if (-not (Test-Path -LiteralPath $BasePython -PathType Leaf)) {
            throw "Python executable is unavailable: $BasePython"
        }
        if (Test-Path -LiteralPath $Root) {
            throw "Lab root already exists; refusing to replace it: $Root"
        }
        $gitCommand = Get-Command git -ErrorAction SilentlyContinue
        if ($null -eq $gitCommand) {
            $gitCommand = Get-Command 'C:\Program Files\Git\cmd\git.exe' -ErrorAction Stop
        }
        $checkout = Join-Path $Root 'repo'
        $venv = Join-Path $Root 'venv'
        $parent = Split-Path $Root -Parent
        if (-not (Test-Path -LiteralPath $parent)) {
            New-Item -ItemType Directory -Path $parent -ErrorAction Stop | Out-Null
        }
        New-Item -ItemType Directory -Path $Root -ErrorAction Stop | Out-Null
        & $gitCommand.Source clone --quiet $Remote $checkout
        if ($LASTEXITCODE -ne 0) { throw "Git clone failed; incomplete lab root retained at $Root" }
        & $gitCommand.Source -C $checkout checkout --quiet --detach $Commit
        if ($LASTEXITCODE -ne 0) { throw "Git checkout failed; incomplete lab root retained at $Root" }
        & $BasePython -m venv $venv
        if ($LASTEXITCODE -ne 0) { throw "Virtual environment creation failed; incomplete lab root retained at $Root" }
        $venvPython = Join-Path $venv 'Scripts\python.exe'
        $installTarget = if ($Monitored) { "${checkout}[windows]" } else { $checkout }
        & $venvPython -m pip install --disable-pip-version-check -e $installTarget | Out-Host
        if ($LASTEXITCODE -ne 0) { throw "Dependency installation failed; incomplete lab root retained at $Root" }
        $importCheck = if ($Monitored) {
            'import vmbox, cryptography, psutil, win32evtlog'
        } else { 'import vmbox, cryptography' }
        & $venvPython -c $importCheck
        if ($LASTEXITCODE -ne 0) { throw "Runtime import check failed; incomplete lab root retained at $Root" }
        $actual = (& $gitCommand.Source -C $checkout rev-parse HEAD).Trim()
        if ($LASTEXITCODE -ne 0 -or $actual -ne $Commit) {
            throw "Prepared checkout revision differs from $Commit"
        }
        [PSCustomObject]@{
            host = $env:COMPUTERNAME
            role = if ($Monitored) { 'monitored' } else { 'anchor' }
            checkout = $checkout
            python = $venvPython
            git_commit = $actual
            runtime_imports = $true
        }
    }

    $monitored = Invoke-Command -Session $monitoredSession -ScriptBlock $prepare `
        -ArgumentList $labRoot, $revision, $GitRemote, $Python, $true
    $anchor = Invoke-Command -Session $anchorSession -ScriptBlock $prepare `
        -ArgumentList $labRoot, $revision, $GitRemote, $Python, $false
    if ($monitored.git_commit -ne $revision -or $anchor.git_commit -ne $revision) {
        throw 'Prepared revisions do not match the laptop checkout.'
    }
    [PSCustomObject]@{
        lab_root = $labRoot
        monitored = $monitored
        anchor = $anchor
        note = 'Runtime preparation only; live recording and anchor behavior not tested yet.'
    } | ConvertTo-Json -Depth 5
}
finally {
    if ($sessions.Count) { Remove-PSSession -Session $sessions }
}
