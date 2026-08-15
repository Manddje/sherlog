<#
.SYNOPSIS
    Collects a complete diagnostics package from an Intune-managed Windows device.

.DESCRIPTION
    Mimics the Intune "Collect diagnostics" action and extends it with:
    - MDM logs via mdmdiagnosticstool.exe (all registered areas)
    - Relevant Event Logs (MDM, Entra/AAD, Device Registration, ESP/Shell-Core)
    - Registry exports (Enrollments, PolicyManager, IME, Autopilot, GPO policies)
    - Identity status (dsregcmd, machine AND interactive-user context), certificates, network info
    - Intune Management Extension (IME) logs
    - Defender support files, Windows Update logs, system reports
    - Co-management, Defender for Endpoint onboarding, Delivery Optimization state
    - Disk space, time sync, TPM status
    - Status of relevant services and scheduled tasks

    Result: a single zip file in C:\Temp (or a custom path), plus a
    _MANIFEST.json describing the run (version, profile, per-step outcome).

.PARAMETER OutputPath
    Folder where the zip file will be created. Default: C:\Temp

.PARAMETER Remote
    Slim profile for unattended/Intune use: skips the slow and large sections
    (msinfo32, Get-WindowsUpdateLog, Defender -GetFiles cab, full-range event
    log export, full mdmdiagnosticstool area zip) so the run stays well under
    the Intune script timeout and the Sherlog upload size limit, while keeping
    the IME logs, event logs (last 14 days), registry, identity and network data.

.PARAMETER UploadUrl
    When set, the resulting zip is uploaded to this Sherlog drop-off endpoint,
    e.g. https://sherlog.nl/api/diagnostics . Requires -UploadToken. Must be
    https:// - a plain http:// URL is refused so the token is never sent in
    cleartext.

.PARAMETER UploadToken
    The self-chosen secret the admin generated on the Sherlog /inbox page. It
    authorizes the upload and is the key to view the uploads at /inbox. It is
    always redacted from every collected text file (including the transcript,
    which PowerShell stamps with the full command line it was invoked with),
    regardless of -Anonymize.

    With -UploadUrl and -UploadToken set, the script also pings
    <base>/api/collect-status at the start of the run and again if it knows the
    run failed, so the inbox can show the device as "collecting" instead of
    staying empty for the minutes the collection takes. The ping carries only
    the phase, the profile, the collector version and the same (optionally
    anonymized) device label as the upload - never log content.

.PARAMETER MaxUploadMB
    Client-side size guard matched against the server's MAX_UPLOAD_MB (default
    100). A package over this size is not uploaded (it would be rejected with
    413 anyway); the local zip is kept.

.PARAMETER Proxy
    Explicit proxy URL for the upload (e.g. http://proxy.contoso.com:8080). If
    omitted, the script tries to auto-detect one from `netsh winhttp show
    proxy`, since a SYSTEM-context run has no per-user WinINET proxy settings
    and would otherwise fail on any proxy-only network.

.PARAMETER Anonymize
    Best-effort redaction of tenant and company data from the package: tenant id,
    tenant/company name, domain(s), UPN/e-mail, device name and user name are
    replaced with placeholders in all TEXT files, and the zip name + upload device
    name are anonymized. Well-known system principals (SYSTEM, NT AUTHORITY, ...)
    are never redacted, since doing so would corrupt registry paths like
    HKEY_LOCAL_MACHINE\SYSTEM\... and break Sherlog's SYSTEM-context detection.
    This is best-effort, NOT a guarantee: binary files (event logs .evtx, Defender
    .cab, the nested mdmdiag .zip) are NOT scrubbed and may still contain
    identifiers - review the package before sharing.

.EXAMPLE
    .\Collect-IntuneDiagnostics.ps1
    .\Collect-IntuneDiagnostics.ps1 -OutputPath D:\Diag

.EXAMPLE
    # Share-safe, best-effort anonymized package:
    .\Collect-IntuneDiagnostics.ps1 -Remote -Anonymize

.EXAMPLE
    # Unattended drop-off (e.g. from an Intune remediation script):
    .\Collect-IntuneDiagnostics.ps1 -Remote `
        -UploadUrl 'https://sherlog.nl/api/diagnostics' -UploadToken '<token>'

.NOTES
    Run as Administrator (elevated PowerShell), or as SYSTEM via Intune.
#>

[CmdletBinding()]
param(
    [string]$OutputPath = 'C:\Temp',
    [switch]$Remote,
    [string]$UploadUrl,
    [string]$UploadToken,
    [int]$MaxUploadMB = 100,
    [string]$Proxy,
    [switch]$Anonymize
)

$ScriptVersion = '1.3.1'

# ============================================================
# 0. Preparation
# ============================================================

# Admin check
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error 'This script must be run as Administrator. Start an elevated PowerShell session and try again.'
    exit 1
}

# Best-effort environment warnings; none of these are fatal, since a degraded
# collection is still more useful than none.
if (-not [Environment]::Is64BitProcess -and [Environment]::Is64BitOperatingSystem) {
    Write-Warning 'Running in 32-bit PowerShell on a 64-bit OS; some paths (e.g. mdmdiagnosticstool.exe) may resolve incorrectly. Re-run in 64-bit PowerShell.'
}
if ($ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') {
    Write-Warning "PowerShell is running in $($ExecutionContext.SessionState.LanguageMode) mode; some collection steps (JSON export, .NET types) may fail under WDAC/CLM restrictions."
}
try {
    $driveLetter = $OutputPath.Substring(0, 1)
    $vol = Get-Volume -DriveLetter $driveLetter -ErrorAction Stop
    if ($vol.SizeRemaining -lt 500MB) {
        Write-Warning "Less than 500 MB free on ${driveLetter}: - collection may fail."
    }
} catch {}

# .NET-formatted output (event level names, error messages) follows this
# thread culture; native console tools (netsh, certutil) still follow the OS
# display language regardless and are NOT made English by this.
try {
    [Threading.Thread]::CurrentThread.CurrentUICulture = [Globalization.CultureInfo]::GetCultureInfo('en-US')
    [Threading.Thread]::CurrentThread.CurrentCulture    = [Globalization.CultureInfo]::GetCultureInfo('en-US')
} catch {}

$ProgressPreference = 'SilentlyContinue'  # large -InFile uploads/copies stay fast on PS 5.1
$PSDefaultParameterValues['Out-File:Encoding'] = 'utf8'

$startedUtc = [DateTime]::UtcNow
$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
# Device label for the zip name and upload header. Anonymized to a stable,
# non-identifying hash of the computer name when -Anonymize is set, so the
# filename and inbox don't leak the hostname.
$deviceLabel = $env:COMPUTERNAME
if ($Anonymize) {
    $h = [System.Security.Cryptography.SHA256]::Create().ComputeHash(
        [Text.Encoding]::UTF8.GetBytes("$env:COMPUTERNAME"))
    $deviceLabel = 'anon-' + (-join ($h[0..3] | ForEach-Object { $_.ToString('x2') }))
}
$work      = Join-Path $OutputPath "IntuneDiag-$deviceLabel-$timestamp"
$zipFile   = "$work.zip"

# TLS 1.2 for every outbound call (the status ping below runs long before the
# upload does; PS 5.1 still defaults to TLS 1.0 on older builds).
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

function Get-SherlogProxy {
    # Auto-detect a configured WinHTTP proxy (SYSTEM has no per-user WinINET
    # settings, so Invoke-RestMethod would otherwise go direct and fail on any
    # proxy-only network) unless one was passed explicitly.
    if ($Proxy) { return $Proxy }
    try {
        $proxyShow = netsh winhttp show proxy 2>$null
        $m = $proxyShow | Select-String 'Proxy Server\(s\)\s*:\s*(\S+)'
        if ($m -and $m.Matches.Count -gt 0) { return 'http://' + $m.Matches[0].Groups[1].Value }
    } catch {}
    return $null
}

function Send-SherlogPing {
    # Collection takes minutes; without this the inbox stays empty until the
    # zip lands and the admin cannot tell "still running" from "never started".
    # Best-effort by design: short timeout, no retries, every failure swallowed
    # - a status ping must never break or slow down the collection itself.
    param([ValidateSet('start','failed')][string]$Phase, [string]$Reason)
    if (-not $UploadUrl -or -not $UploadToken) { return }
    if ($UploadToken -eq '<PASTE-YOUR-TOKEN-HERE>') { return }
    if ($UploadUrl -notmatch '^https://') { return }
    try {
        $base = ($UploadUrl -replace '/api/diagnostics/?$', '')
        $profileName = if ($Remote) { 'remote' } else { 'full' }
        # The reason is an error string, so treat it as untrusted: never let
        # the token ride along, keep it ASCII (PS 5.1 mangles non-ASCII in
        # -Body) and short - the server caps it again anyway.
        $r = "$Reason" -replace [regex]::Escape($UploadToken), '<redacted>'
        $r = $r -replace '[^\x20-\x7E]', ' '
        if ($r.Length -gt 200) { $r = $r.Substring(0, 200) }
        $body = @{ phase = $Phase; reason = $r; profile = $profileName } |
                ConvertTo-Json -Compress
        $pingArgs = @{
            Uri = "$base/api/collect-status"; Method = 'Post'; Body = $body
            ContentType = 'application/json'; TimeoutSec = 10
            Headers = @{
                'X-Upload-Token'      = $UploadToken
                'X-Device-Name'       = $deviceLabel
                'X-Collector-Version' = $ScriptVersion
            }
        }
        $pingProxy = Get-SherlogProxy
        if ($pingProxy) { $pingArgs['Proxy'] = $pingProxy }
        Invoke-RestMethod @pingArgs | Out-Null
    } catch {}
}

# Any unhandled terminating error still tells Sherlog the run died, so the
# device shows as failed instead of silently expiring. Lives here and not in
# the Intune remediation wrapper: the wrapper does not know the anonymized
# device label and would leak the real hostname in -Anonymize mode.
trap { try { Send-SherlogPing -Phase failed -Reason "collection aborted: $($_.Exception.Message)" } catch {}; break }

Send-SherlogPing -Phase start

$folders = @('MDM','EventLogs','Registry','Identity','Network','Apps-IME','System','Defender','WindowsUpdate','Autopilot','Management')
foreach ($f in $folders) {
    New-Item -ItemType Directory -Path (Join-Path $work $f) -Force | Out-Null
}

$transcript = Join-Path $work 'CollectionTranscript.log'
Start-Transcript -Path $transcript -Force | Out-Null

$StepLog = [System.Collections.Generic.List[object]]::new()

function Write-Step { param([string]$Msg) Write-Host "[$(Get-Date -Format 'HH:mm:ss')] $Msg" -ForegroundColor Cyan }
function Invoke-Safe {
    param([string]$Name, [scriptblock]$Action)
    Write-Step $Name
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $prevEAP = $ErrorActionPreference
    try {
        # Non-terminating cmdlet errors (a bad path, a missing log) otherwise
        # print a message but leave the step looking like it succeeded; force
        # them to be caught here so a failed step is recorded as failed.
        $ErrorActionPreference = 'Stop'
        & $Action
        $StepLog.Add([pscustomobject]@{ Name = $Name; Ok = $true; Error = $null
            Seconds = [math]::Round($sw.Elapsed.TotalSeconds, 1) })
    } catch {
        Write-Warning "  Failed: $($_.Exception.Message)"
        $StepLog.Add([pscustomobject]@{ Name = $Name; Ok = $false; Error = $_.Exception.Message
            Seconds = [math]::Round($sw.Elapsed.TotalSeconds, 1) })
    } finally {
        $ErrorActionPreference = $prevEAP
    }
}

# ============================================================
# 1. MDM logs (mdmdiagnosticstool)
# ============================================================
Invoke-Safe 'MDM diagnostics report...' {
    # The all-areas zip duplicates the event logs and registry exports below
    # and is the single largest item in the package; skip it in the slim
    # remote profile and keep only the small default report.
    if (-not $Remote) {
        $areaKey = 'HKLM:\SOFTWARE\Microsoft\MdmDiagnostics\Area'
        if (Test-Path $areaKey) {
            $areas = (Get-ChildItem $areaKey).PSChildName -join ';'
            Write-Host "  Areas found: $areas"
            & "$env:windir\system32\mdmdiagnosticstool.exe" -area $areas -zip (Join-Path $work 'MDM\MDMDiag-AllAreas.zip') | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "mdmdiagnosticstool -area exited with code $LASTEXITCODE" }
        }
    }
    & "$env:windir\system32\mdmdiagnosticstool.exe" -out (Join-Path $work 'MDM\DefaultReport') | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "mdmdiagnosticstool -out exited with code $LASTEXITCODE" }
}

# ============================================================
# 2. Event Logs
# ============================================================
$eventLogs = @{
    'DeviceManagement-Admin'      = 'Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin'
    'DeviceManagement-Operational'= 'Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Operational'
    'AAD-Operational'             = 'Microsoft-Windows-AAD/Operational'
    'UserDeviceRegistration'      = 'Microsoft-Windows-User Device Registration/Admin'
    'Shell-Core'                  = 'Microsoft-Windows-Shell-Core/Operational'
    'ModernDeployment-Autopilot'  = 'Microsoft-Windows-ModernDeployment-Diagnostics-Provider/Autopilot'
    'ModernDeployment-Diagnostics'= 'Microsoft-Windows-ModernDeployment-Diagnostics-Provider/ManagementService'
    'Provisioning-Diagnostics'    = 'Microsoft-Windows-Provisioning-Diagnostics-Provider/Admin'
    'CodeIntegrity'               = 'Microsoft-Windows-CodeIntegrity/Operational'
    'TaskScheduler'               = 'Microsoft-Windows-TaskScheduler/Operational'
    'PushNotification-Platform'   = 'Microsoft-Windows-PushNotification-Platform/Operational'
    # SCEP/PKCS certificate enrollment + renewal failures surface here long
    # before the expiring MDM cert itself becomes visible.
    'CertificateServicesClient'   = 'Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational'
    'LAPS'                        = 'Microsoft-Windows-LAPS/Operational'
    'Application'                 = 'Application'
    'System'                      = 'System'
}
$eventLogWindowDays = 14

foreach ($entry in $eventLogs.GetEnumerator()) {
    Invoke-Safe "Event log: $($entry.Key)..." {
        $dest = Join-Path $work "EventLogs\$($entry.Key).evtx"
        if ($Remote) {
            # Slim profile: only the last N days in the raw export too - the
            # biggest single size contributor on a chatty Application/System log.
            $q = "*[System[TimeCreated[timediff(@SystemTime) <= $($eventLogWindowDays * 86400000)]]]"
            wevtutil epl $entry.Value $dest "/q:$q" /ow:true 2>$null
        } else {
            wevtutil epl $entry.Value $dest /ow:true 2>$null
        }
        if ($LASTEXITCODE -ne 0) {
            throw "wevtutil exited with code $LASTEXITCODE (log may not be registered on this device)"
        }
        # Errors/warnings/criticals from the last $eventLogWindowDays days,
        # filtered server-side by Get-WinEvent so -MaxEvents caps the matching
        # events, not the newest raw entries - a busy Application/System log
        # would otherwise summarize to zero (the newest 200 raw entries are
        # almost always informational).
        $records = Get-WinEvent -FilterHashtable @{
            LogName   = $entry.Value
            Level     = 1, 2, 3
            StartTime = (Get-Date).AddDays(-$eventLogWindowDays)
        } -MaxEvents 200 -ErrorAction SilentlyContinue
        if ($records) {
            $records | Select-Object TimeCreated, Id, LevelDisplayName, Message |
                Format-List | Out-File (Join-Path $work "EventLogs\$($entry.Key)-ErrorsWarnings.txt") -Width 250
            # Locale-invariant sidecar: numeric Level survives non-English
            # Windows, where LevelDisplayName ("Fout"/"Fehler"/...) breaks the
            # text-based error/warning count.
            $records | Select-Object TimeCreated, Id, Level, LevelDisplayName, Message |
                ConvertTo-Json -Depth 3 | Out-File (Join-Path $work "EventLogs\$($entry.Key)-ErrorsWarnings.json")
        }
    }
}

# ============================================================
# 3. Registry exports
# ============================================================
$regKeys = @{
    'Enrollments'              = 'HKLM\SOFTWARE\Microsoft\Enrollments'
    'PolicyManager-Current'    = 'HKLM\SOFTWARE\Microsoft\PolicyManager\current'
    'PolicyManager-Providers'  = 'HKLM\SOFTWARE\Microsoft\PolicyManager\Providers'
    'IntuneManagementExtension'= 'HKLM\SOFTWARE\Microsoft\IntuneManagementExtension'
    'Win32Apps'                = 'HKLM\SOFTWARE\Microsoft\IntuneManagementExtension\Win32Apps'
    'Autopilot'                = 'HKLM\SOFTWARE\Microsoft\Provisioning\Diagnostics\AutoPilot'
    'Autopilot-EstablishedCorr'= 'HKLM\SOFTWARE\Microsoft\Provisioning\AutopilotSettings'
    'EnrollmentStatusTracking' = 'HKLM\SOFTWARE\Microsoft\Windows\Autopilot\EnrollmentStatusTracking'
    'FirstSync'                = 'HKLM\SOFTWARE\Microsoft\Windows\Autopilot'
    'CloudDomainJoin'          = 'HKLM\SYSTEM\CurrentControlSet\Control\CloudDomainJoin'
    'OMADM-Accounts'           = 'HKLM\SOFTWARE\Microsoft\Provisioning\OMADM\Accounts'
    'MDM-Uninstall'            = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
    'InternetSettings'         = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings'
    # GPO-vs-Intune conflicts (e.g. MDMWinsOverGP) are a common real-world
    # cause of policy drift; correlate against the PolicyManager RSOP above.
    'Policies'                 = 'HKLM\SOFTWARE\Policies'
    'CoManagement'             = 'HKLM\SOFTWARE\Microsoft\CCM'
    'DefenderATP-Onboarding'   = 'HKLM\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status'
    # Per-CSP applied-value cache: what the DM client actually set, next to
    # the PolicyManager intent above.
    'NodeCache'                = 'HKLM\SOFTWARE\Microsoft\Provisioning\NodeCache\CSP\Device\MS DM Server\Nodes'
    # Policy only, never password material; key is absent on most devices
    # (the step then records a clean failure in the manifest).
    'LAPS-Policy'              = 'HKLM\SOFTWARE\Microsoft\Policies\LAPS'
}

foreach ($entry in $regKeys.GetEnumerator()) {
    Invoke-Safe "Registry: $($entry.Key)..." {
        reg export $entry.Value (Join-Path $work "Registry\$($entry.Key).reg") /y 2>$null | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "reg export exited with code $LASTEXITCODE (key may not exist on this device)" }
    }
}

# ============================================================
# 4. Identity & certificates
# ============================================================
Invoke-Safe 'dsregcmd /status (machine/SYSTEM context)...' {
    dsregcmd /status | Out-File (Join-Path $work 'Identity\dsregcmd-status.txt')
}

# The Primary Refresh Token is per-user: dsregcmd run as SYSTEM (the usual
# Intune remediation context) can never see it. Best-effort: run dsregcmd as
# the interactively logged-on user via a one-shot scheduled task, so the PRT
# check has a real signal instead of always reading "unknown".
Invoke-Safe 'dsregcmd /status (interactive user context)...' {
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    $userName = $cs.UserName
    if (-not $userName) {
        Write-Host '  No interactive user session found; skipping.'
        return
    }
    $outFile = Join-Path $work 'Identity\dsregcmd-status-user.txt'
    $taskName = 'SherlogDsregcmd-' + [guid]::NewGuid().ToString('N').Substring(0, 8)
    $cmd = "dsregcmd /status > `"$outFile`" 2>&1"
    schtasks /Create /TN $taskName /TR "cmd.exe /c $cmd" /SC ONCE /ST 00:00 /RU $userName /RL LIMITED /F | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "schtasks /Create exited with code $LASTEXITCODE" }
    try {
        schtasks /Run /TN $taskName | Out-Null
        $deadline = (Get-Date).AddSeconds(20)
        do {
            Start-Sleep -Milliseconds 500
            $info = schtasks /Query /TN $taskName /FO LIST /V 2>$null
            $running = $info -match 'Status:\s*Running'
        } while ($running -and (Get-Date) -lt $deadline)
    } finally {
        schtasks /Delete /TN $taskName /F 2>$null | Out-Null
    }
    if (-not (Test-Path $outFile)) {
        Write-Host '  User-context dsregcmd produced no output (session may be locked/disconnected).'
    }
}

Invoke-Safe 'Certificates (machine + user)...' {
    certutil -store MY  | Out-File (Join-Path $work 'Identity\certs-machine-MY.txt')
    certutil -store -user MY | Out-File (Join-Path $work 'Identity\certs-user-MY.txt')

    # Highlight the machine certificates, including the Intune MDM device cert
    Get-ChildItem Cert:\LocalMachine\My |
        Select-Object Subject, Issuer, NotBefore, NotAfter, Thumbprint, @{n='Expired';e={$_.NotAfter -lt (Get-Date)}} |
        Format-List | Out-File (Join-Path $work 'Identity\certs-machine-overview.txt')
}

# ============================================================
# 5. Network
# ============================================================
Invoke-Safe 'Network configuration...' {
    ipconfig /all                          | Out-File (Join-Path $work 'Network\ipconfig.txt')
    netsh advfirewall show allprofiles     | Out-File (Join-Path $work 'Network\firewall-profiles.txt')
    netsh advfirewall show global          | Out-File (Join-Path $work 'Network\firewall-global.txt')
    netsh winhttp show proxy               | Out-File (Join-Path $work 'Network\winhttp-proxy.txt')
    netsh wlan show profiles               | Out-File (Join-Path $work 'Network\wlan-profiles.txt')
    route print                            | Out-File (Join-Path $work 'Network\routes.txt')
    Get-DnsClientServerAddress | Format-Table -AutoSize | Out-File (Join-Path $work 'Network\dns-servers.txt')
    # Locale-invariant twin of the firewall state: netsh's ON/OFF text is
    # localized, Get-NetFirewallProfile's Enabled is a plain boolean.
    Get-NetFirewallProfile -ErrorAction SilentlyContinue |
        Select-Object Name, Enabled |
        ConvertTo-Json | Out-File (Join-Path $work 'Network\firewall-profiles.json')
}

Invoke-Safe 'Connectivity test to Intune/Entra endpoints...' {
    $endpoints = @(
        'login.microsoftonline.com',
        'enterpriseregistration.windows.net',
        'enrollment.manage.microsoft.com',
        'portal.manage.microsoft.com',
        'graph.microsoft.com',
        'nps.notify.windows.com',
        'client.wns.windows.com',
        'ztd.dds.microsoft.com',
        'cs.dds.microsoft.com',
        'manage.microsoft.com',
        'dl.delivery.mp.microsoft.com',
        'emdl.ws.microsoft.com',
        'autologon.microsoftazuread-sso.com'
    )
    $results = foreach ($ep in $endpoints) {
        $t = Test-NetConnection -ComputerName $ep -Port 443 -WarningAction SilentlyContinue
        [pscustomobject]@{
            Endpoint  = $ep
            Reachable = $t.TcpTestSucceeded
            RemoteIP  = "$($t.RemoteAddress)"
        }
    }
    $results | Format-Table -AutoSize | Out-File (Join-Path $work 'Network\endpoint-connectivity.txt')
    # Locale-invariant twin (same pattern as firewall-profiles.json).
    $results | ConvertTo-Json | Out-File (Join-Path $work 'Network\endpoint-connectivity.json')

    # TLS-inspection detection: a plain port-443 handshake only proves *a* TLS
    # server answered. A real request's certificate issuer should be a
    # Microsoft/DigiCert CA; a locally-installed inspection proxy substitutes
    # its own issuer, which explains a lot of otherwise-mysterious app/sync
    # failures on managed networks.
    try {
        $req = [Net.HttpWebRequest]::Create('https://login.microsoftonline.com/')
        $req.Timeout = 5000
        $resp = $req.GetResponse()
        $cert = $req.ServicePoint.Certificate
        $issuer = if ($cert) { $cert.Issuer } else { 'unknown' }
        $resp.Close()
        "TLS certificate issuer for login.microsoftonline.com: $issuer" |
            Out-File (Join-Path $work 'Network\tls-issuer-check.txt')
    } catch {
        "TLS probe failed: $($_.Exception.Message)" |
            Out-File (Join-Path $work 'Network\tls-issuer-check.txt')
    }
}

# ============================================================
# 6. Apps / Intune Management Extension
# ============================================================
Invoke-Safe 'Copying IME logs...' {
    $imeLogs = "$env:ProgramData\Microsoft\IntuneManagementExtension\Logs"
    if (Test-Path $imeLogs) {
        if ($Remote) {
            # Slim profile: recent logs only (rotated archives go back months)
            # and a running size cap so the package stays uploadable.
            $dest = Join-Path $work 'Apps-IME\Logs'
            New-Item -ItemType Directory -Path $dest -Force | Out-Null
            $budget = 40MB
            Get-ChildItem $imeLogs -File -Recurse |
                Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-14) } |
                Sort-Object LastWriteTime -Descending | ForEach-Object {
                    if ($budget -ge $_.Length) {
                        Copy-Item $_.FullName (Join-Path $dest $_.Name) -Force
                        $budget -= $_.Length
                    }
                }
        } else {
            Copy-Item $imeLogs (Join-Path $work 'Apps-IME\Logs') -Recurse -Force
        }
    }
}

Invoke-Safe 'IME service status...' {
    Get-Service -Name 'IntuneManagementExtension','Microsoft Intune Management Extension' -ErrorAction SilentlyContinue |
        Select-Object Name, Status, StartType |
        Format-Table -AutoSize | Out-File (Join-Path $work 'Apps-IME\service-status.txt')
}

Invoke-Safe 'Inventorying installed apps...' {
    $paths = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
             'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    Get-ItemProperty $paths -ErrorAction SilentlyContinue |
        Where-Object DisplayName |
        Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
        Sort-Object DisplayName |
        Format-Table -AutoSize | Out-File (Join-Path $work 'Apps-IME\installed-apps.txt') -Width 250
}

# ============================================================
# 6b. Co-management, Defender for Endpoint, Delivery Optimization
# ============================================================
Invoke-Safe 'Co-management state...' {
    $flags = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\CCM' -ErrorAction SilentlyContinue
    $svc = Get-Service -Name 'CcmExec' -ErrorAction SilentlyContinue
    [pscustomobject]@{
        CcmExecService    = if ($svc) { $svc.Status.ToString() } else { 'not installed' }
        CoManagementFlags = $flags.CoManagementFlags
    } | Format-List | Out-File (Join-Path $work 'Management\co-management.txt')
}

Invoke-Safe 'Defender for Endpoint onboarding...' {
    $atp = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status' -ErrorAction SilentlyContinue
    $sense = Get-Service -Name 'Sense' -ErrorAction SilentlyContinue
    [pscustomobject]@{
        SenseService    = if ($sense) { $sense.Status.ToString() } else { 'not installed' }
        OnboardingState = $atp.OnboardingState
        OrgId           = $atp.OrgId
    } | Format-List | Out-File (Join-Path $work 'Management\defender-atp-onboarding.txt')
}

Invoke-Safe 'Delivery Optimization status...' {
    Get-DeliveryOptimizationStatus -ErrorAction SilentlyContinue |
        Out-File (Join-Path $work 'Management\delivery-optimization-status.txt')
    Get-DeliveryOptimizationPerfSnap -ErrorAction SilentlyContinue |
        Out-File (Join-Path $work 'Management\delivery-optimization-perf.txt')
}

# ============================================================
# 7. System
# ============================================================
if (-not $Remote) {
    Invoke-Safe 'msinfo32 report (this may take a while)...' {
        Start-Process msinfo32 -ArgumentList "/report `"$(Join-Path $work 'System\msinfo32.log')`"" -Wait
    }
}

Invoke-Safe 'Drivers, battery, OS info...' {
    pnputil /enum-drivers | Out-File (Join-Path $work 'System\drivers.txt')
    powercfg /batteryreport /output (Join-Path $work 'System\battery-report.html') 2>$null
    Get-ComputerInfo | Out-File (Join-Path $work 'System\computerinfo.txt')
    Get-HotFix | Sort-Object InstalledOn -Descending |
        Format-Table -AutoSize | Out-File (Join-Path $work 'System\hotfixes.txt')
}

Invoke-Safe 'Relevant scheduled tasks...' {
    $emTasks = Get-ScheduledTask -TaskPath '\Microsoft\Windows\EnterpriseMgmt\*' -ErrorAction SilentlyContinue
    $emTasks | Select-Object TaskPath, TaskName, State |
        Format-Table -AutoSize | Out-File (Join-Path $work 'System\enterprisemgmt-tasks.txt') -Width 250
    # JSON twin with run results: LastTaskResult answers "does the sync
    # schedule actually fire and succeed", which the State column cannot.
    $emTasks | ForEach-Object {
        $i = $_ | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue
        [pscustomobject]@{
            TaskName       = $_.TaskName
            TaskPath       = $_.TaskPath
            State          = $_.State.ToString()
            LastRunTime    = if ($i -and $i.LastRunTime)  { $i.LastRunTime.ToString('o') } else { $null }
            LastTaskResult = if ($i) { $i.LastTaskResult } else { $null }
            NextRunTime    = if ($i -and $i.NextRunTime)  { $i.NextRunTime.ToString('o') } else { $null }
        }
    } | ConvertTo-Json | Out-File (Join-Path $work 'System\enterprisemgmt-tasks.json')
}

Invoke-Safe 'Key service states...' {
    Get-Service -Name 'IntuneManagementExtension','dmwappushservice','WpnService',
        'wuauserv','DoSvc','W32Time','CcmExec','Sense','WinDefend','Schedule' -ErrorAction SilentlyContinue |
        Select-Object Name,
            @{n='Status';e={$_.Status.ToString()}},
            @{n='StartType';e={$_.StartType.ToString()}} |
        ConvertTo-Json | Out-File (Join-Path $work 'System\services.json')
}

Invoke-Safe 'BitLocker / Secure Boot state...' {
    Get-BitLockerVolume -ErrorAction SilentlyContinue |
        Select-Object MountPoint,
            @{n='VolumeStatus';e={$_.VolumeStatus.ToString()}},
            @{n='ProtectionStatus';e={$_.ProtectionStatus.ToString()}},
            EncryptionPercentage,
            @{n='KeyProtectors';e={@($_.KeyProtector | ForEach-Object { $_.KeyProtectorType.ToString() })}} |
        ConvertTo-Json -Depth 3 | Out-File (Join-Path $work 'System\bitlocker.json')
    # null = legacy BIOS / not queryable (distinct from $false = disabled).
    $sb = try { Confirm-SecureBootUEFI } catch { $null }
    @{ SecureBoot = $sb } | ConvertTo-Json | Out-File (Join-Path $work 'System\secureboot.json')
}

Invoke-Safe 'Pending reboot state...' {
    @{
        CbsRebootPending  = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
        WuRebootRequired  = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
        PendingFileRename = [bool](Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue)
    } | ConvertTo-Json | Out-File (Join-Path $work 'System\pending-reboot.json')
}

Invoke-Safe 'Device info (build, boot, locale)...' {
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
    @{
        LastBootUtc    = $os.LastBootUpTime.ToUniversalTime().ToString('o')
        OSBuild        = "$($cv.CurrentBuildNumber).$($cv.UBR)"
        DisplayVersion = "$($cv.DisplayVersion)"
        Edition        = "$($cv.EditionID)"
        Locale         = (Get-Culture).Name
        TimeZone       = (Get-TimeZone).Id
    } | ConvertTo-Json | Out-File (Join-Path $work 'System\device-info.json')
}

Invoke-Safe 'Devices in error state...' {
    Get-PnpDevice -Status Error -ErrorAction SilentlyContinue |
        Select-Object FriendlyName, Class,
            @{n='Status';e={$_.Status.ToString()}} |
        ConvertTo-Json | Out-File (Join-Path $work 'System\pnp-errors.json')
}

Invoke-Safe 'Time sync status...' {
    w32tm /query /status | Out-File (Join-Path $work 'System\time-sync-status.txt')
    if ($LASTEXITCODE -ne 0) { throw "w32tm exited with code $LASTEXITCODE" }
}

Invoke-Safe 'Disk space...' {
    Get-Volume -ErrorAction SilentlyContinue |
        Where-Object { $_.DriveLetter } |
        Select-Object DriveLetter, FileSystemLabel,
            @{n='SizeGB';e={[math]::Round($_.Size / 1GB, 1)}},
            @{n='FreeGB';e={[math]::Round($_.SizeRemaining / 1GB, 1)}} |
        Format-Table -AutoSize | Out-File (Join-Path $work 'System\disk-space.txt')
}

Invoke-Safe 'TPM status...' {
    Get-Tpm -ErrorAction SilentlyContinue | Format-List | Out-File (Join-Path $work 'System\tpm-status.txt')
}

# ============================================================
# 8. Defender
# ============================================================
Invoke-Safe 'Defender support files...' {
    # -GetFiles produces a large cab; skip it in the slim remote profile.
    if (-not $Remote) {
        $mpcmd = "$env:ProgramFiles\Windows Defender\mpcmdrun.exe"
        if (Test-Path $mpcmd) {
            & $mpcmd -GetFiles | Out-Null
            Copy-Item "$env:ProgramData\Microsoft\Windows Defender\Support\MpSupportFiles.cab" `
                      (Join-Path $work 'Defender') -Force -ErrorAction SilentlyContinue
        }
    }
    Get-MpComputerStatus -ErrorAction SilentlyContinue |
        Out-File (Join-Path $work 'Defender\mp-status.txt')
}

# ============================================================
# 9. Windows Update
# ============================================================
# Cheap registry-only Windows Update for Business state, collected in both
# profiles; the slow parts (Get-WindowsUpdateLog, the raw USO *.etl traces
# Sherlog cannot read anyway) stay full-profile only.
Invoke-Safe 'Windows Update for Business state...' {
    Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' -ErrorAction SilentlyContinue |
        Format-List | Out-File (Join-Path $work 'WindowsUpdate\wufb-ux-settings.txt')
    Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -ErrorAction SilentlyContinue |
        Format-List | Out-File (Join-Path $work 'WindowsUpdate\wufb-policy.txt')
}

Invoke-Safe 'Windows Update history...' {
    # COM history is cheap and structured, unlike the ETL-based
    # Get-WindowsUpdateLog. ResultCode: 2=Succeeded, 3=SucceededWithErrors,
    # 4=Failed, 5=Aborted.
    $session  = New-Object -ComObject Microsoft.Update.Session
    $searcher = $session.CreateUpdateSearcher()
    $n = [Math]::Min($searcher.GetTotalHistoryCount(), 30)
    if ($n -gt 0) {
        $searcher.QueryHistory(0, $n) | ForEach-Object {
            [pscustomobject]@{
                Date       = $_.Date.ToString('o')
                Title      = $_.Title
                ResultCode = $_.ResultCode
                HResult    = $_.HResult
            }
        } | ConvertTo-Json | Out-File (Join-Path $work 'WindowsUpdate\wu-history.json')
    }
}

if (-not $Remote) {
    Invoke-Safe 'Windows Update log (this may take a while)...' {
        Get-WindowsUpdateLog -LogPath (Join-Path $work 'WindowsUpdate\WindowsUpdate.log') -ErrorAction SilentlyContinue | Out-Null
    }
}

# ============================================================
# 10. Autopilot / ESP extras
# ============================================================
Invoke-Safe 'Autopilot/ESP files...' {
    Copy-Item "$env:windir\Logs\Panther\unattendgc\setupact.log" (Join-Path $work 'Autopilot') -Force -ErrorAction SilentlyContinue
    Copy-Item "$env:ProgramData\Microsoft\Provisioning\*.log" (Join-Path $work 'Autopilot') -Force -ErrorAction SilentlyContinue
}

# ============================================================
# 11. Generate summary
# ============================================================
Invoke-Safe 'Generating summary...' {
    $dsreg = dsregcmd /status
    function Get-DsregField($name) {
        $m = $dsreg | Select-String ('^\s*' + [regex]::Escape($name) + '\s*:\s*(.+?)\s*$') | Select-Object -First 1
        if ($m -and $m.Matches.Count -gt 0) { $m.Matches[0].Groups[1].Value } else { '' }
    }
    $aadJoined = Get-DsregField 'AzureAdJoined'
    $prt       = Get-DsregField 'AzureAdPrt'
    $mdmUrl    = Get-DsregField 'MdmUrl'

    $imeService = (Get-Service -Name 'IntuneManagementExtension' -ErrorAction SilentlyContinue).Status

    $recentErrors = Get-WinEvent -LogName 'Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin' -MaxEvents 500 -ErrorAction SilentlyContinue |
        Where-Object Level -eq 2 |
        Select-Object -First 10 TimeCreated, Id, Message

    $anonLine = if ($Anonymize) {
        "`n [Anonymized] Best-effort redaction of tenant/company/device data in" +
        " TEXT files. Binaries (evtx/cab/mdmdiag-zip) are NOT scrubbed -" +
        " review before sharing.`n"
    } else { '' }

    $summary = @"
==========================================================
 INTUNE DIAGNOSTICS SUMMARY
 Device   : $env:COMPUTERNAME
 Date     : $(Get-Date)
 User     : $env:USERNAME
 Collector: v$ScriptVersion ($(if ($Remote) { 'Remote' } else { 'Full' }) profile)
==========================================================
$anonLine

[Identity]
  AzureAdJoined : $aadJoined
  AzureAdPrt    : $prt
  MDM URL       : $mdmUrl

[Services]
  IntuneManagementExtension : $imeService

[Last 10 MDM errors (DeviceManagement Admin log)]
$($recentErrors | Format-List | Out-String)

See the subfolders for all details:
  MDM\           - mdmdiagnosticstool output (HTML report, registry dump, evtx)
  EventLogs\     - evtx exports + errors/warnings as text and JSON (incl. push, cert enrollment, LAPS)
  Registry\      - Enrollments, PolicyManager, NodeCache, IME, Autopilot, OMADM accounts, GPO policies
  Identity\      - dsregcmd (machine + interactive user), certificates
  Network\       - ipconfig, proxy, firewall, endpoint connectivity (txt+json), TLS-issuer check
  Apps-IME\      - IME logs, app inventory
  Management\    - co-management, Defender for Endpoint onboarding, Delivery Optimization
  System\        - msinfo32, drivers, hotfixes, scheduled tasks (+run results), services,
                   BitLocker/Secure Boot, pending reboot, device info, PnP errors,
                   disk space, time sync, TPM
  Defender\      - MpSupportFiles.cab, status
  WindowsUpdate\ - WindowsUpdate.log, WUfB settings, update history (json)
  Autopilot\     - setupact.log, provisioning logs
  _MANIFEST.json - collector version, profile and per-step outcome
==========================================================
"@
    $summary | Out-File (Join-Path $work '_SUMMARY.txt')
    Write-Host $summary
}

# ============================================================
# 11b. Collection manifest
# ============================================================
Invoke-Safe 'Writing manifest...' {
    $manifest = [pscustomobject]@{
        CollectorVersion = $ScriptVersion
        Profile          = if ($Remote) { 'Remote' } else { 'Full' }
        RunAsSystem      = ($env:USERNAME -eq 'SYSTEM' -or $env:USERDOMAIN -eq 'NT AUTHORITY')
        RunAsUser        = "$env:USERDOMAIN\$env:USERNAME"
        Anonymized       = [bool]$Anonymize
        StartedUtc       = $startedUtc.ToString('o')
        FinishedUtc      = ([DateTime]::UtcNow).ToString('o')
        OSBuild          = [Environment]::OSVersion.VersionString
        PSVersion        = $PSVersionTable.PSVersion.ToString()
        Steps            = $StepLog
    }
    $manifest | ConvertTo-Json -Depth 4 | Out-File (Join-Path $work '_MANIFEST.json')
}

# ============================================================
# 11c. Secret redaction (always) + best-effort anonymization (-Anonymize)
# Stop the transcript first so CollectionTranscript.log can be scrubbed too.
# ============================================================
Stop-Transcript | Out-Null

function Invoke-TextRedaction {
    param(
        [Parameter(Mandatory)] [string]$Root,
        [System.Collections.Generic.List[object]]$Map = [System.Collections.Generic.List[object]]::new(),
        [switch]$AlsoRedactEmails
    )
    if ($Map.Count -eq 0 -and -not $AlsoRedactEmails) { return 0 }
    $seen = @{}
    $final = foreach ($r in ($Map | Sort-Object { $_.Value.Length } -Descending)) {
        $k = $r.Value.ToLowerInvariant()
        if (-not $seen.ContainsKey($k)) { $seen[$k] = $true; $r }
    }
    # Compile every literal token once instead of parsing the pattern again for
    # every file: the map is small but the file set is not.
    $rxOpts = [Text.RegularExpressions.RegexOptions]::IgnoreCase -bor
              [Text.RegularExpressions.RegexOptions]::Compiled
    $rules = foreach ($r in $final) {
        [pscustomobject]@{ Re = [regex]::new([regex]::Escape($r.Value), $rxOpts); Tag = $r.Tag }
    }

    # E-mail catch-all, anchored on the literal '@' so the engine can skip
    # through a multi-MB IME log at native speed. A pattern that starts with
    # the local part instead ([A-Z0-9._%+-]+@...) tries - and backtracks out
    # of - every GUID, hash and base64 run in the file; that is what made
    # -Anonymize run for minutes on log-heavy devices. The local part is
    # walked backwards from the match, bounded by its own length.
    $emailRe = [regex]::new('@[A-Z0-9.-]+\.[A-Z]{2,}', $rxOpts)
    $isLocal = New-Object 'bool[]' 128
    foreach ($c in [char[]]'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._%+-') {
        $isLocal[[int]$c] = $true
    }
    function Remove-EmailAddresses([string]$t) {
        if ($t.IndexOf('@') -lt 0) { return $t }
        $sb = [Text.StringBuilder]::new($t.Length)
        $pos = 0
        foreach ($m in $emailRe.Matches($t)) {
            if ($m.Index -lt $pos) { continue }
            $s = $m.Index
            while ($s -gt $pos -and [int]$t[$s - 1] -lt 128 -and $isLocal[[int]$t[$s - 1]]) { $s-- }
            if ($s -eq $m.Index) { continue }   # bare '@domain' is not an address
            [void]$sb.Append($t, $pos, $s - $pos).Append('<EMAIL>')
            $pos = $m.Index + $m.Length
        }
        if ($pos -eq 0) { return $t }
        [void]$sb.Append($t, $pos, $t.Length - $pos)
        return $sb.ToString()
    }

    $textExt = '.txt', '.log', '.reg', '.xml', '.html', '.htm', '.json', '.csv', '.ini', '.config'
    $count = 0
    Get-ChildItem $Root -Recurse -File |
        Where-Object { $textExt -contains $_.Extension.ToLower() } | ForEach-Object {
            try {
                $bytes = [IO.File]::ReadAllBytes($_.FullName)
                if ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) {
                    $enc = [Text.Encoding]::Unicode
                } elseif ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFE -and $bytes[1] -eq 0xFF) {
                    $enc = [Text.Encoding]::BigEndianUnicode
                } elseif ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
                    $enc = New-Object Text.UTF8Encoding($true)
                } else {
                    $enc = New-Object Text.UTF8Encoding($false)
                }
                $text = $enc.GetString($bytes)
                if ($text.Length -gt 0 -and $text[0] -eq [char]0xFEFF) { $text = $text.Substring(1) }
                $orig = $text
                foreach ($r in $rules) {
                    # IsMatch first: Replace copies the whole (multi-MB) string
                    # even when nothing matches, and most tokens appear in only
                    # a handful of files. Same engine, so same semantics.
                    if ($r.Re.IsMatch($text)) { $text = $r.Re.Replace($text, $r.Tag) }
                }
                if ($AlsoRedactEmails) { $text = Remove-EmailAddresses $text }
                if ($text -ne $orig) {
                    [IO.File]::WriteAllBytes($_.FullName, $enc.GetPreamble() + $enc.GetBytes($text))
                    $count++
                }
            } catch { Write-Warning "  Could not redact $($_.Name): $($_.Exception.Message)" }
        }
    return $count
}

# The upload secret is always redacted from every text file (chiefly the
# transcript, which PowerShell stamps with the full command line it was
# invoked with, including -UploadToken) - independent of -Anonymize.
# Both jobs share one walk over the package: a separate pass per job reads,
# decodes, re-encodes and rewrites every text file a second time, and on a
# log-heavy device that walk is the slow part of -Anonymize. The token entry
# is added first and outside any step, so a failure while collecting the
# anonymization tokens can never cost us the secret redaction.
$redactMap = [System.Collections.Generic.List[object]]::new()
if ($UploadToken) {
    $redactMap.Add([pscustomobject]@{ Value = $UploadToken; Tag = '<UPLOAD-TOKEN>' })
}

if ($Anonymize) {
    Invoke-Safe 'Collecting anonymization tokens...' {
        # Principals that must never be redacted: they are not identifying and
        # (for SYSTEM/NT AUTHORITY) redacting them corrupts registry paths
        # like HKEY_LOCAL_MACHINE\SYSTEM\... and breaks the server's
        # SYSTEM-context detection for the Entra PRT check.
        $wellKnown = '(?i)^(NT AUTHORITY\\SYSTEM|SYSTEM|NT AUTHORITY|LOCAL SERVICE|NETWORK SERVICE|' +
                     'NT AUTHORITY\\LOCAL SERVICE|NT AUTHORITY\\NETWORK SERVICE|WORKGROUP|Unknown|N/A|None)$'
        function Add-Redact($val, $tag) {
            if ($null -eq $val) { return }
            $v = "$val".Trim()
            if ($v.Length -ge 4 -and $v -notmatch $wellKnown) {
                $redactMap.Add([pscustomobject]@{ Value = $v; Tag = $tag })
            }
        }
        $dsreg = dsregcmd /status
        function Get-Dsreg($name) {
            $line = $dsreg | Select-String ('^\s*' + [regex]::Escape($name) + '\s*:\s*(.+?)\s*$') | Select-Object -First 1
            if ($line -and $line.Matches.Count -gt 0) { $line.Matches[0].Groups[1].Value } else { '' }
        }
        Add-Redact (Get-Dsreg 'TenantId')               '<TENANT-ID>'
        Add-Redact (Get-Dsreg 'TenantName')             '<TENANT>'
        Add-Redact (Get-Dsreg 'TenantDisplayName')      '<COMPANY>'
        Add-Redact (Get-Dsreg 'Executing Account Name') '<UPN>'

        Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo' `
            -ErrorAction SilentlyContinue | ForEach-Object {
                $p = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
                Add-Redact $p.TenantId    '<TENANT-ID>'
                Add-Redact $p.TenantName  '<TENANT>'
                Add-Redact $p.UserEmail   '<UPN>'
                Add-Redact $p.DisplayName '<COMPANY>'
            }

        $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' `
            -ErrorAction SilentlyContinue
        Add-Redact $cv.RegisteredOrganization '<COMPANY>'
        Add-Redact $cv.RegisteredOwner        '<USER>'

        Add-Redact $env:COMPUTERNAME '<DEVICE>'
        Add-Redact $env:USERNAME     '<USER>'
        Add-Redact $env:USERDNSDOMAIN '<DOMAIN>'
        Add-Redact $env:USERDOMAIN    '<DOMAIN>'
        # Domain part of any UPN we found.
        foreach ($u in @($redactMap | Where-Object { $_.Tag -eq '<UPN>' })) {
            if ($u.Value -match '@(.+)$') { Add-Redact $matches[1] '<DOMAIN>' }
        }
        Write-Host "  Collected $($redactMap.Count) token(s) to redact."
    }
}

if ($redactMap.Count -gt 0 -or $Anonymize) {
    Invoke-Safe 'Redacting text files...' {
        $n = Invoke-TextRedaction -Root $work -Map $redactMap -AlsoRedactEmails:$Anonymize
        Write-Host "  Redacted $n file(s) using $($redactMap.Count) token(s)."
    }
}

if ($Anonymize) {
    Write-Warning ('ANONYMIZE is best-effort and NOT a guarantee. Only TEXT files were ' +
        'redacted; binary files (event logs .evtx, Defender .cab, the nested ' +
        'mdmdiag .zip) are NOT scrubbed and may still contain tenant/company ' +
        'identifiers. Review the package before sharing.')
}

# ============================================================
# 12. Package everything
# ============================================================
Write-Step 'Packaging everything...'
try {
    if (Test-Path $zipFile) { Remove-Item $zipFile -Force -ErrorAction SilentlyContinue }
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [IO.Compression.ZipFile]::CreateFromDirectory($work, $zipFile, [IO.Compression.CompressionLevel]::Optimal, $false)
} finally {
    Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ''
Write-Host "Done! Diagnostics package: $zipFile" -ForegroundColor Green

# ============================================================
# 13. Optional upload to Sherlog (drop-off API)
# ============================================================
# Best-effort cleanup of zips left behind by earlier failed runs in the same
# output folder, so a device that repeatedly fails to upload (offline, no
# token yet) doesn't fill the disk one package at a time.
Invoke-Safe 'Pruning old local packages...' {
    Get-ChildItem $OutputPath -Filter 'IntuneDiag-*.zip' -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -ne $zipFile -and $_.LastWriteTime -lt (Get-Date).AddDays(-7) } |
        Remove-Item -Force -ErrorAction SilentlyContinue
}

if ($UploadUrl) {
    if (-not $UploadToken -or $UploadToken -eq '<PASTE-YOUR-TOKEN-HERE>') {
        Write-Warning 'UploadUrl set without a real UploadToken; skipping upload. Local zip kept.'
    } elseif ($UploadUrl -notmatch '^https://') {
        Write-Warning 'UploadUrl is not https:// - refusing to upload (would send the token in cleartext). Local zip kept.'
    } else {
        $sizeMB = [math]::Round((Get-Item $zipFile).Length / 1MB, 1)
        if ($sizeMB -gt $MaxUploadMB) {
            Write-Warning "Package is $sizeMB MB, over the $MaxUploadMB MB limit; skipping upload (would be rejected). Local zip kept: $zipFile"
            Write-Output "SHERLOG_ERROR=package too large ($sizeMB MB > $MaxUploadMB MB), not uploaded"
            Send-SherlogPing -Phase failed -Reason "package too large ($sizeMB MB > $MaxUploadMB MB), not uploaded"
        } else {
            Write-Step "Uploading to $UploadUrl ($sizeMB MB)..."
            # Re-detected rather than cached: a VPN or proxy change during a
            # long collection must not leave the upload with a stale proxy.
            $uploadProxy = Get-SherlogProxy

            $headers = @{
                'X-Upload-Token'      = $UploadToken
                'X-Device-Name'       = $deviceLabel
                'X-Collector-Version' = $ScriptVersion
            }
            $maxAttempts = 3
            $uploaded = $false
            for ($attempt = 1; $attempt -le $maxAttempts -and -not $uploaded; $attempt++) {
                try {
                    $irmArgs = @{
                        Uri = $UploadUrl; Method = 'Post'; InFile = $zipFile
                        ContentType = 'application/zip'; Headers = $headers; TimeoutSec = 180
                    }
                    if ($uploadProxy) { $irmArgs['Proxy'] = $uploadProxy }
                    $resp = Invoke-RestMethod @irmArgs
                    $base = ($UploadUrl -replace '/api/diagnostics/?$', '')
                    $resultUrl = "$base$($resp.url)"
                    Write-Host "Uploaded. Review at: $resultUrl" -ForegroundColor Green
                    Remove-Item $zipFile -Force -ErrorAction SilentlyContinue
                    $uploaded = $true
                    # Single deterministic line for automation (e.g. the Intune
                    # remediation wrapper) - independent of -ForegroundColor
                    # and of Write-Host/Write-Warning, neither of which flows
                    # through a normal PowerShell pipe.
                    Write-Output "SHERLOG_RESULT=$resultUrl"
                } catch {
                    $status = $null
                    try { $status = [int]$_.Exception.Response.StatusCode } catch {}
                    $serverMsg = $_.ErrorDetails.Message
                    $reason = if ($serverMsg) { $serverMsg } else { $_.Exception.Message }
                    $permanent = $status -in 400, 401, 403, 404, 413
                    if ($permanent -or $attempt -eq $maxAttempts) {
                        Write-Warning "Upload failed ($status): $reason. Local zip kept: $zipFile"
                        Write-Output "SHERLOG_ERROR=upload failed ($status): $reason"
                        Send-SherlogPing -Phase failed -Reason "upload failed ($status): $reason"
                    } else {
                        Write-Host "  Attempt $attempt/$maxAttempts failed ($status): $reason - retrying..."
                        Start-Sleep -Seconds (5 * $attempt)
                    }
                }
            }
        }
    }
}
