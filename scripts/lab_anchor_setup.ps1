# Set up one isolated anchor trial from the laptop. Private signing key stays on anchor.
# Run in Windows PowerShell with the two temporary lab-account credentials.
[CmdletBinding()]
param(
    [string]$LabRoot = 'C:\VmboxLab\479a15e7-d7a17fe0',
    [string]$MonitoredAddress = '192.168.189.128',
    [string]$AnchorAddress = '192.168.189.129',
    [string]$MonitoredUser = 'ajjj\vmboxlab',
    [string]$AnchorUser = 'VMBOX-ANCHOR\vmboxlab'
)

$ErrorActionPreference = 'Stop'
if ($MonitoredAddress -eq $AnchorAddress) { throw 'VM addresses must differ.' }
$trial = [guid]::NewGuid().ToString('N').Substring(0, 8)
$anchorKeys = Join-Path $LabRoot "anchor_keys_$trial"
$anchorLedger = Join-Path $LabRoot "anchor_ledger_$trial"
$hostKeys = Join-Path $LabRoot "anchor_public_$trial"
$evidence = Join-Path $LabRoot "live_$trial"
$anchorPython = Join-Path $LabRoot 'venv\Scripts\python.exe'
$anchorRepo = Join-Path $LabRoot 'repo'

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

    $generated = Invoke-Command -Session $anchorSession -ArgumentList $anchorRepo, $anchorPython, $anchorKeys, $anchorLedger, $MonitoredAddress, $trial -ScriptBlock {
        param($Repo, $Python, $Keys, $Ledger, $HostAddress, $Trial)
        if (-not (Test-Path -LiteralPath $Repo -PathType Container) -or
            -not (Test-Path -LiteralPath $Python -PathType Leaf)) {
            throw 'Prepared anchor checkout or Python environment is missing.'
        }
        if ((Test-Path -LiteralPath $Keys) -or (Test-Path -LiteralPath $Ledger)) {
            throw 'Trial key or ledger path already exists; refusing to reuse it.'
        }
        Push-Location $Repo
        try {
            $keygenOutput = @(& $Python -m vmbox.cli anchor-keygen --out $Keys 2>&1)
            if ($LASTEXITCODE -ne 0) {
                throw "Anchor key generation failed: $($keygenOutput -join '; ')"
            }
        }
        finally { Pop-Location }
        $ruleName = "VMBOX-Anchor-8765-$Trial"
        New-NetFirewallRule -Name $ruleName -DisplayName "V-MBOX anchor lab $Trial" `
            -Direction Inbound -Action Allow -Protocol TCP -LocalPort 8765 `
            -RemoteAddress $HostAddress -Profile Any -ErrorAction Stop | Out-Null
        [PSCustomObject]@{
            keygen_output = $keygenOutput -join '; '
            firewall_rule = $ruleName
        }
    }

    $bundle = Invoke-Command -Session $anchorSession -ArgumentList $anchorKeys -ScriptBlock {
        param($Keys)
        [PSCustomObject]@{
            public = [Convert]::ToBase64String([IO.File]::ReadAllBytes((Join-Path $Keys 'public.pem')))
            auth = [Convert]::ToBase64String([IO.File]::ReadAllBytes((Join-Path $Keys 'auth.key')))
        }
    }
    $hostFiles = Invoke-Command -Session $monitoredSession -ArgumentList $hostKeys, $bundle.public, $bundle.auth -ScriptBlock {
        param($Directory, $PublicBase64, $AuthBase64)
        if (Test-Path -LiteralPath $Directory) {
            throw 'Monitored VM key directory already exists; refusing to replace it.'
        }
        New-Item -ItemType Directory -Path $Directory -ErrorAction Stop | Out-Null
        [IO.File]::WriteAllBytes((Join-Path $Directory 'public.pem'),
            [Convert]::FromBase64String($PublicBase64))
        [IO.File]::WriteAllBytes((Join-Path $Directory 'auth.key'),
            [Convert]::FromBase64String($AuthBase64))
        [PSCustomObject]@{
            public_key = Join-Path $Directory 'public.pem'
            auth_key = Join-Path $Directory 'auth.key'
            private_key_present = Test-Path -LiteralPath (Join-Path $Directory 'private.pem')
        }
    }
    $bundle = $null
    if ($hostFiles.private_key_present) { throw 'Private key unexpectedly present on monitored VM.' }
    [PSCustomObject]@{
        trial = $trial
        lab_root = $LabRoot
        anchor_ip = $AnchorAddress
        monitored_ip = $MonitoredAddress
        anchor_keys = $anchorKeys
        anchor_ledger = $anchorLedger
        monitored_keys = $hostKeys
        evidence = $evidence
        firewall_rule = $generated.firewall_rule
        keygen = $generated.keygen_output
        note = 'Keys prepared; anchor listener and live recording have not started.'
    } | ConvertTo-Json -Depth 4
}
finally {
    if ($sessions.Count) { Remove-PSSession -Session $sessions }
}
