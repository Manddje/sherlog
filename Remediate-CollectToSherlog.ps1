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

    Runs as SYSTEM. Output is kept short to fit the 2048-char output cap. Skips
    collection if it already ran within the last $MinHoursBetweenRuns hours
    (stamped in the registry), so a recurring remediation schedule doesn't spam
    the inbox or burn the upload caps across a large fleet.

.NOTES
    Edit the two settings below. Generate the token on the Sherlog /inbox page.
    Run in 64-bit PowerShell. Paste as the Detection script (it always runs).
#>

# ---- settings -------------------------------------------------------------
$SherlogBase = 'https://sherlog.nl'          # your Sherlog base URL
$UploadToken = '<PASTE-YOUR-TOKEN-HERE>'     # from <SherlogBase>/inbox
$MinHoursBetweenRuns = 6                     # skip if collected more recently
$CollectionMode      = 'full'                # 'anon' when the /inbox Anonymize toggle is on
# ---------------------------------------------------------------------------

if ($UploadToken -eq '<PASTE-YOUR-TOKEN-HERE>' -or $UploadToken.Length -lt 24) {
    Write-Output 'Sherlog: UploadToken not configured (edit the script settings).'
    exit 1
}

$stateKey = 'HKLM:\SOFTWARE\Sherlog'
# Throttle per collection mode: switching full<->anon uses a different value
# name, so a mode change always forces a fresh collection instead of being
# suppressed by the previous mode's timestamp.
$runValue = "LastRunUtc_$CollectionMode"
try {
    $last = (Get-ItemProperty -Path $stateKey -Name $runValue -ErrorAction Stop).$runValue
    $lastUtc = [DateTime]::Parse($last, $null, [Globalization.DateTimeStyles]::RoundtripKind)
    $hoursSince = ((Get-Date).ToUniversalTime() - $lastUtc).TotalHours
    if ($hoursSince -lt $MinHoursBetweenRuns) {
        Write-Output "Sherlog: collected $([math]::Round($hoursSince,1))h ago in '$CollectionMode' mode, skipping (min $MinHoursBetweenRuns h)."
        exit 0
    }
} catch {}

try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
} catch {}

# Admin-only working directory: $env:TEMP (C:\Windows\Temp under SYSTEM) is
# writable by standard users, so a downloaded script and the diagnostics zip
# (full tenant data) would both be plantable/readable there.
$workDir = Join-Path $env:ProgramData 'Sherlog'
try {
    New-Item -ItemType Directory -Path $workDir -Force | Out-Null
    icacls $workDir /inheritance:r | Out-Null
    icacls $workDir /grant:r 'SYSTEM:(OI)(CI)F' 'BUILTIN\Administrators:(OI)(CI)F' | Out-Null
} catch {}

$collector = Join-Path $workDir 'Collect-IntuneDiagnostics.ps1'
try {
    Invoke-WebRequest -Uri "$SherlogBase/collect-script" -OutFile $collector -UseBasicParsing
} catch {
    Write-Output "Sherlog: collector download failed: $($_.Exception.Message)"
    exit 1
}

$resultLine = $null
try {
    # -Anonymize is driven solely by $CollectionMode (single source of truth);
    # the /inbox generator flips that variable, not this call.
    $collectorArgs = @(
        '-Remote', '-OutputPath', $workDir,
        '-UploadUrl', "$SherlogBase/api/diagnostics",
        '-UploadToken', $UploadToken
    )
    if ($CollectionMode -eq 'anon') { $collectorArgs += '-Anonymize' }
    $output = & $collector @collectorArgs 2>&1
    $resultLine = $output | Where-Object { $_ -match '^SHERLOG_(RESULT|ERROR)=' } | Select-Object -Last 1
} catch {
    Write-Output "Sherlog: collection failed: $($_.Exception.Message)"
    exit 1
} finally {
    Remove-Item $collector -Force -ErrorAction SilentlyContinue
}

# Stamp the throttle timestamp only on a successful upload, so a failed run
# does not poison the window and block retries for the next $MinHoursBetweenRuns.
try {
    if ($resultLine -match '^SHERLOG_RESULT=(.+)$') {
        New-Item -Path $stateKey -Force | Out-Null
        Set-ItemProperty -Path $stateKey -Name $runValue -Value ((Get-Date).ToUniversalTime().ToString('o'))
        Set-ItemProperty -Path $stateKey -Name LastResultUrl -Value $matches[1]
    }
} catch {}

if ($resultLine) {
    Write-Output "Sherlog: $resultLine"
} else {
    Write-Output 'Sherlog: collector ran but produced no result line (upload may have been skipped - see UploadUrl/UploadToken).'
}

exit 0
