# Export a read-only copy of one session's anchor receipts to the monitored VM.
# Run on the laptop; no signing key or shared auth key is transferred.
[CmdletBinding()]
param(
    [string]$LabRoot = 'C:\VmboxLab\479a15e7-d7a17fe0',
    [string]$Trial = '89982d6f',
    [string]$MonitoredAddress = '192.168.189.128',
    [string]$AnchorAddress = '192.168.189.129',
    [string]$MonitoredUser = 'ajjj\vmboxlab',
    [string]$AnchorUser = 'VMBOX-ANCHOR\vmboxlab'
)

$ErrorActionPreference = 'Stop'
if ($Trial -notmatch '^[0-9a-f]{8}$') { throw 'Trial must be eight lowercase hex characters.' }
$evidence = Join-Path $LabRoot "live_$Trial"
$ledger = Join-Path $LabRoot "anchor_ledger_$Trial"
$export = Join-Path $LabRoot "anchor_export_$Trial"
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

    $sessionId = Invoke-Command -Session $monitoredSession -ArgumentList $evidence -ScriptBlock {
        param($Evidence)
        $manifestPath = Join-Path $Evidence 'manifest.json'
        if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
            throw 'Live evidence manifest is missing.'
        }
        $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
        if ($manifest.mode -ne 'live' -or $manifest.session_id -notmatch
            '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') {
            throw 'Manifest is not a valid live session.'
        }
        [string]$manifest.session_id
    }
    $files = @(Invoke-Command -Session $anchorSession -ArgumentList $ledger, $sessionId -ScriptBlock {
        param($Ledger, $SessionId)
        $directory = Join-Path (Join-Path $Ledger 'receipts') $SessionId
        if (-not (Test-Path -LiteralPath $directory -PathType Container)) {
            throw 'Anchor has no receipt directory for this live session.'
        }
        foreach ($file in Get-ChildItem -LiteralPath $directory -File | Sort-Object Name) {
            if ($file.Name -notmatch '^receipt_[0-9]{8}\.json$') {
                throw "Unexpected anchor receipt filename: $($file.Name)"
            }
            [PSCustomObject]@{
                name = $file.Name
                bytes = [Convert]::ToBase64String([IO.File]::ReadAllBytes($file.FullName))
                sha256 = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
            }
        }
    })
    if ($files.Count -eq 0) { throw 'Anchor receipt directory is empty.' }
    $copied = Invoke-Command -Session $monitoredSession -ArgumentList $export, $sessionId, $files -ScriptBlock {
        param($Export, $SessionId, $Files)
        if (Test-Path -LiteralPath $Export) {
            throw 'Anchor export path already exists; refusing to overwrite it.'
        }
        $directory = Join-Path (Join-Path $Export 'receipts') $SessionId
        New-Item -ItemType Directory -Path $directory -ErrorAction Stop | Out-Null
        foreach ($file in $Files) {
            if ($file.name -notmatch '^receipt_[0-9]{8}\.json$') {
                throw 'Invalid receipt name in transfer.'
            }
            $path = Join-Path $directory $file.name
            [IO.File]::WriteAllBytes($path, [Convert]::FromBase64String($file.bytes))
            $actual = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($actual -ne $file.sha256) { throw "Receipt transfer hash mismatch: $($file.name)" }
        }
        $Files.Count
    }
    [PSCustomObject]@{
        session_id = $sessionId
        anchor_receipts = $files.Count
        copied_receipts = $copied
        export_on_monitored_vm = $export
        note = 'Read-only anchor receipt copy; original anchor ledger and host evidence unchanged.'
    } | ConvertTo-Json -Depth 3
}
finally {
    if ($sessions.Count) { Remove-PSSession -Session $sessions }
}
