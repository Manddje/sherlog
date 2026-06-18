<#
.SYNOPSIS
    Intune Remediation DETECTION script: collect a slim Intune diagnostics
    package and upload it to a Sherlog drop-off inbox.

.DESCRIPTION
    Intune Remediations require a detection script; paste this in the DETECTION
    slot (no remediation script needed). Create it under Devices > Scripts and
    remediations, assign it to a group, or run it on-demand ("Run remediation").
    It downloads Collect-IntuneDiagnostics.ps1 from your Sherlog server, runs it
    with the slim -Remote profile and uploads the zip with your token. Review the
    uploads on <SherlogBase>/inbox (enter your token in the form).

    Runs as SYSTEM. Output is kept short to fit the 2048-char output cap.

.NOTES
    Edit the two settings below. Generate the token on the Sherlog /inbox page.
    Run in 64-bit PowerShell. Paste as the Detection script (it always runs).
#>

# ---- settings -------------------------------------------------------------
$SherlogBase = 'https://sherlog.nl'          # your Sherlog base URL
$UploadToken = '<PASTE-YOUR-TOKEN-HERE>'     # from <SherlogBase>/inbox
# ---------------------------------------------------------------------------

try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
} catch {}

$collector = Join-Path $env:TEMP 'Collect-IntuneDiagnostics.ps1'
try {
    Invoke-WebRequest -Uri "$SherlogBase/collect-script" -OutFile $collector -UseBasicParsing
} catch {
    Write-Output "Sherlog: collector download failed: $($_.Exception.Message)"
    exit 1
}

try {
    & $collector -Remote -OutputPath $env:TEMP `
        -UploadUrl "$SherlogBase/api/diagnostics" -UploadToken $UploadToken |
        Where-Object { $_ -match 'Review at:|Upload failed' } |
        Select-Object -Last 1 |
        ForEach-Object { Write-Output "Sherlog: $_" }
} catch {
    Write-Output "Sherlog: collection failed: $($_.Exception.Message)"
    exit 1
} finally {
    Remove-Item $collector -Force -ErrorAction SilentlyContinue
}

exit 0
