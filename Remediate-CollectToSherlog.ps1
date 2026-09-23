<#
.SYNOPSIS
    Intune Remediation DETECTION script: collect a slim Intune diagnostics
    package and upload it to a Sherlog drop-off inbox.

.DESCRIPTION
    Intune Remediations require a detection script; paste this in the DETECTION
    slot (no remediation script needed). Create it under Devices > Scripts and
    remediations, assign it to a group, or run it on-demand ("Run remediation").
    It downloads Collect-IntuneDiagnostics.ps1 from your Sherlog server,
    verifies it against the SHA-256 pinned below, runs it with the slim -Remote
    profile and uploads the zip with the device upload token. Review the
    uploads on <SherlogBase>/inbox with your inbox key.

    Runs as SYSTEM. Everything the collector prints is captured; the Intune
    output (capped at 2048 chars) is a single short "Sherlog: ..." line.
    Exit code 0 = uploaded (or skipped by the throttle), 1 = failed or not
    configured, so a failed run shows up as "With issues" in Intune.

    Throttle: a successful collection is stamped per collection mode in
    HKLM\SOFTWARE\Sherlog (LastRunUtc_<mode>); the next run within
    $MinHoursBetweenRuns hours is skipped, so a recurring schedule doesn't
    spam the inbox or burn the upload caps across a large fleet. Switching
    full<->anon uses a different value, so a mode change always collects.
    A failed run is stamped too (LastFailUtc_<mode>, FailCount_<mode>) and
    retried after 1 h, doubling per consecutive failure up to
    $MinHoursBetweenRuns. A stamp that lies in the future (clock moved
    backwards) counts as expired. Set $Force = $true for an on-demand run
    that ignores both. Only the run time and the first 8 characters of the
    upload id are stored - never the result link, which is a bearer link to
    the package.

.NOTES
    The settings are filled in by the Sherlog /inbox page. $CollectorSha256 is
    the SHA-256 of the collector the server serves; the /inbox page and the
    server's download fill it in. When the collector on the server changes,
    re-copy this script (a stale pin makes every run fail closed).
    Run in 64-bit PowerShell. Paste as the Detection script (it always runs).
#>

# ---- settings -------------------------------------------------------------
$SherlogBase = 'https://sherlog.nl'          # your Sherlog base URL
$UploadToken = '<PASTE-YOUR-TOKEN-HERE>'     # device upload token (shu_...) from <SherlogBase>/inbox
$CollectorSha256 = '<COLLECTOR-SHA256>'
$MinHoursBetweenRuns = 6                     # skip if collected more recently
$CollectionMode      = 'full'                # 'anon' when the /inbox Anonymize toggle is on
$Force               = $false                # $true: ignore throttle + failure backoff
# ---------------------------------------------------------------------------

$WrapperVersion = '1.4.0'
$ProgressPreference = 'SilentlyContinue'

# ============================================================================
# Shared helpers. The proxy and folder-ACL functions below are byte-identical
# copies of the ones in Collect-IntuneDiagnostics.ps1 (a test enforces this):
# this script is pasted into Intune on its own and cannot dot-source them.
# ============================================================================

function Enable-SherlogTls12 {
    # Add TLS 1.2 without dropping what is already enabled (TLS 1.3 or
    # SystemDefault on newer .NET). SystemDefault (0) already lets the OS pick.
    try {
        $current = [Net.ServicePointManager]::SecurityProtocol
        if ([int]$current -ne 0 -and -not ($current -band [Net.SecurityProtocolType]::Tls12)) {
            [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        }
    } catch { Write-Verbose "TLS setup: $($_.Exception.Message)" }
}

function Protect-SherlogText {
    # One short, single-line, ASCII-only string that never carries the secret:
    # used for the Intune output line and for the status-ping reason (PS 5.1
    # mangles non-ASCII in -Body; the server caps the reason again anyway).
    param([string]$Text, [string]$Secret, [int]$Max = 400)
    $t = "$Text"
    if ($Secret) { $t = $t -replace [regex]::Escape($Secret), '<redacted>' }
    $t = ($t -replace '[^\x20-\x7E]+', ' ').Trim()
    if ($t.Length -gt $Max) { $t = $t.Substring(0, $Max) + '...' }
    return $t
}

function ConvertFrom-SherlogProxyServer {
    # WinHTTP proxy string -> proxy URL for https traffic, or $null.
    # Accepts 'host:port', 'http://host:port' and the per-protocol form
    # 'http=a:80;https=b:443' (https wins, then http; socks/ftp-only is
    # unusable for Invoke-WebRequest and yields $null).
    param([string]$Server)
    if (-not $Server) { return $null }
    $plain = $null
    $perProtocol = @{}
    foreach ($entry in ($Server -split '[;\s]+')) {
        if (-not $entry) { continue }
        if ($entry -match '^([A-Za-z]+)=(.+)$') {
            $perProtocol[$matches[1].ToLowerInvariant()] = $matches[2]
        } elseif (-not $plain) {
            $plain = $entry
        }
    }
    $chosen = $plain
    if ($perProtocol.ContainsKey('https')) { $chosen = $perProtocol['https'] }
    elseif ($perProtocol.ContainsKey('http')) { $chosen = $perProtocol['http'] }
    if (-not $chosen) { return $null }
    if ($chosen -match '^https?://') { return $chosen.TrimEnd('/') }
    if ($chosen -match '^[A-Za-z][A-Za-z0-9+.-]*://') { return $null }
    return 'http://' + $chosen.TrimEnd('/')
}

function ConvertFrom-SherlogWinHttpSetting {
    # Decodes the WinHttpSettings REG_BINARY (what `netsh winhttp set proxy`
    # writes): DWORD size, DWORD counter, DWORD flags (1 = direct,
    # 2 = proxy bit), DWORD len + ASCII proxy, DWORD len + ASCII bypass list.
    # Returns Server/Bypass ('' Server = direct), or $null when unreadable.
    param([byte[]]$Bytes)
    if (-not $Bytes -or $Bytes.Length -lt 16) { return $null }
    $flags = [BitConverter]::ToInt32($Bytes, 8)
    $server = ''
    $bypass = ''
    if ($flags -band 2) {
        $len = [BitConverter]::ToInt32($Bytes, 12)
        if ($len -lt 0 -or 16 + $len -gt $Bytes.Length) { return $null }
        $server = [Text.Encoding]::ASCII.GetString($Bytes, 16, $len)
        $offset = 16 + $len
        if ($offset + 4 -le $Bytes.Length) {
            $blen = [BitConverter]::ToInt32($Bytes, $offset)
            if ($blen -gt 0 -and $offset + 4 + $blen -le $Bytes.Length) {
                $bypass = [Text.Encoding]::ASCII.GetString($Bytes, $offset + 4, $blen)
            }
        }
    }
    return [pscustomobject]@{ Server = $server.Trim([char]0, ' '); Bypass = $bypass.Trim([char]0, ' ') }
}

function Get-SherlogNetshProxy {
    # Locale-independent parse of `netsh winhttp show proxy`: the labels are
    # translated ("Proxy Server(s)", "Proxyserver", ...), but the layout is
    # always "  <label> :  <value>" with the proxy first and the bypass list
    # second. "Direct access (no proxy server)." has no such line.
    param([string[]]$Lines)
    $values = @(foreach ($line in $Lines) {
        if ($line -match '^\s+\S[^:]*?\s*:\s+(\S.*?)\s*$') { $matches[1] }
    })
    if ($values.Count -eq 0) { return [pscustomobject]@{ Server = ''; Bypass = '' } }
    $bypass = ''
    if ($values.Count -gt 1) { $bypass = $values[1] }
    return [pscustomobject]@{ Server = $values[0]; Bypass = $bypass }
}

function Test-SherlogProxyBypass {
    # True when $HostName matches the WinHTTP bypass list ('<local>' = any
    # dot-less host name, '*' wildcards, ';' or whitespace separated).
    param([string]$HostName, [string]$Bypass)
    if (-not $HostName -or -not $Bypass) { return $false }
    foreach ($pattern in ($Bypass -split '[;,\s]+')) {
        if (-not $pattern) { continue }
        if ($pattern -eq '<local>') {
            if ($HostName -notmatch '\.') { return $true }
            continue
        }
        $pattern = $pattern -replace '^[A-Za-z]+://', ''
        if ($HostName -like $pattern) { return $true }
    }
    return $false
}

function Get-SherlogProxy {
    # SYSTEM has no per-user WinINET proxy, so Invoke-WebRequest/RestMethod
    # would go direct and fail on any proxy-only network. Use an explicit
    # proxy when given, else the machine WinHTTP proxy (registry first, then
    # netsh as a fallback), honouring its bypass list. Deliberately not
    # cached: a VPN/proxy change during a long run must not leave a stale one.
    param([string]$TargetUrl, [string]$Explicit)
    if ($Explicit) { return $Explicit }
    $targetHost = ''
    try { $targetHost = ([Uri]$TargetUrl).Host } catch { $targetHost = '' }
    if ($targetHost -in @('localhost', '127.0.0.1', '::1', '[::1]')) { return $null }
    $ErrorActionPreference = 'Continue'
    $config = $null
    try {
        $raw = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections' `
                    -Name WinHttpSettings -ErrorAction Stop).WinHttpSettings
        $config = ConvertFrom-SherlogWinHttpSetting -Bytes $raw
    } catch { $config = $null }
    if ($null -eq $config) {
        try { $config = Get-SherlogNetshProxy -Lines @(netsh.exe winhttp show proxy 2>$null) } catch { $config = $null }
    }
    if ($null -eq $config -or -not $config.Server) { return $null }
    if (Test-SherlogProxyBypass -HostName $targetHost -Bypass $config.Bypass) { return $null }
    return (ConvertFrom-SherlogProxyServer -Server $config.Server)
}

function Remove-SherlogTree {
    # Deletes a file or a directory tree WITHOUT following junctions or
    # symlinks: a reparse point is removed as a link and its target is never
    # touched. Windows PowerShell 5.1's Remove-Item -Recurse does descend into
    # junctions, which would let a planted link delete files elsewhere.
    param([Parameter(Mandatory = $true)][string]$Path)
    try { $attr = [IO.File]::GetAttributes($Path) } catch { return }
    $isLink = [bool]($attr -band [IO.FileAttributes]::ReparsePoint)
    if ($attr -band [IO.FileAttributes]::Directory) {
        if (-not $isLink) {
            foreach ($child in [IO.Directory]::GetFileSystemEntries($Path)) {
                Remove-SherlogTree -Path $child
            }
        }
        [IO.Directory]::Delete($Path, $false)
    } else {
        if (-not $isLink -and ($attr -band [IO.FileAttributes]::ReadOnly)) {
            [IO.File]::SetAttributes($Path, [IO.FileAttributes]::Normal)
        }
        [IO.File]::Delete($Path)
    }
}

function New-SherlogDirSecurity {
    # Protected ACL (no inheritance from the parent): owner Administrators,
    # full control for SYSTEM and Administrators only. SIDs, never names:
    # 'BUILTIN\Administrators' is localized on non-English Windows.
    $system = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
    $admins = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
    $security = New-Object System.Security.AccessControl.DirectorySecurity
    $security.SetAccessRuleProtection($true, $false)
    $security.SetOwner($admins)
    foreach ($sid in @($system, $admins)) {
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $sid, 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow')
        $security.AddAccessRule($rule)
    }
    return $security
}

function Test-SherlogDirAcl {
    # True only for a real (non-reparse) directory owned by SYSTEM or
    # Administrators whose DACL is protected and holds ACEs for exactly those
    # two SIDs - a standard user who pre-created the folder keeps neither
    # ownership nor an explicit ACE past this check.
    param([Parameter(Mandatory = $true)][string]$Path)
    $allowed = @('S-1-5-18', 'S-1-5-32-544')
    try {
        $attr = [IO.File]::GetAttributes($Path)
        if (-not ($attr -band [IO.FileAttributes]::Directory)) { return $false }
        if ($attr -band [IO.FileAttributes]::ReparsePoint) { return $false }
        $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
        $owner = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
        if ($allowed -notcontains $owner) { return $false }
        if (-not $acl.AreAccessRulesProtected) { return $false }
        $rules = @($acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))
        if ($rules.Count -eq 0) { return $false }
        foreach ($rule in $rules) {
            if ($allowed -notcontains $rule.IdentityReference.Value) { return $false }
        }
        return $true
    } catch {
        return $false
    }
}

function Initialize-SherlogDir {
    # Creates (or re-secures) a SYSTEM/Administrators-only directory and
    # verifies the result. A pre-existing folder that still carries a foreign
    # owner or ACE after the ACL is applied is taken over, removed (without
    # following reparse points) and recreated once; $false if still wrong.
    # -MustBeNew: fail instead of reusing an existing path (per-run folders).
    param([Parameter(Mandatory = $true)][string]$Path, [switch]$MustBeNew)
    if ($MustBeNew) {
        # GetAttributes also sees a dangling link, which Test-Path misses.
        $taken = $true
        try { [void][IO.File]::GetAttributes($Path) } catch { $taken = $false }
        if ($taken) { return $false }
    }
    for ($attempt = 1; $attempt -le 2; $attempt++) {
        try {
            $exists = $true
            try { $attr = [IO.File]::GetAttributes($Path) } catch { $exists = $false }
            if ($exists -and (-not ($attr -band [IO.FileAttributes]::Directory) -or
                              ($attr -band [IO.FileAttributes]::ReparsePoint))) {
                Remove-SherlogTree -Path $Path
                $exists = $false
            }
            if (-not $exists) { New-Item -ItemType Directory -Path $Path -ErrorAction Stop | Out-Null }
            if (Test-SherlogDirAcl -Path $Path) { return $true }
            Set-Acl -LiteralPath $Path -AclObject (New-SherlogDirSecurity) -ErrorAction Stop
            if (Test-SherlogDirAcl -Path $Path) { return $true }
        } catch {
            Write-Verbose "Securing $Path failed: $($_.Exception.Message)"
        }
        if ($attempt -eq 2) { break }
        # Foreign owner/ACE survived: take ownership (takeown enables the
        # privilege itself; only the exit code is used, the text is
        # localized), then start over from an empty path.
        $ErrorActionPreference = 'Continue'
        try { takeown.exe /F $Path /A 2>$null | Out-Null } catch { Write-Verbose 'takeown failed' }
        try { Set-Acl -LiteralPath $Path -AclObject (New-SherlogDirSecurity) -ErrorAction Stop } catch { Write-Verbose 'Set-Acl after takeown failed' }
        try { Remove-SherlogTree -Path $Path } catch { Write-Verbose "Removing $Path failed: $($_.Exception.Message)" }
    }
    return $false
}

# ============================================================================
# Wrapper-only helpers
# ============================================================================

function Get-SherlogHoursSince {
    # Hours since an ISO-8601 UTC stamp; $null when missing/unparseable or
    # in the future (clock moved backwards) - both count as "expired".
    param([object]$Stamp, [DateTime]$NowUtc)
    if (-not $Stamp) { return $null }
    try {
        $then = [DateTime]::Parse("$Stamp", [Globalization.CultureInfo]::InvariantCulture,
                                  [Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime()
    } catch { return $null }
    $hours = ($NowUtc - $then).TotalHours
    if ($hours -lt 0) { return $null }
    return $hours
}

function Get-SherlogSkipReason {
    # Throttle + failure backoff decision; pure, so it is unit-tested.
    # $State: hashtable/object with LastRunUtc_<mode>, LastFailUtc_<mode>,
    # FailCount_<mode>. Returns $null (run) or an object with ExitCode/Message.
    param($State, [string]$Mode, [DateTime]$NowUtc, [double]$MinHours)
    if ($null -eq $State) { return $null }
    $sinceRun = Get-SherlogHoursSince -Stamp $State."LastRunUtc_$Mode" -NowUtc $NowUtc
    if ($null -ne $sinceRun -and $sinceRun -lt $MinHours) {
        return [pscustomobject]@{
            ExitCode = 0
            Message  = "collected $([math]::Round($sinceRun, 1))h ago in '$Mode' mode, skipping (min $MinHours h; set `$Force = `$true to run now)."
        }
    }
    $fails = 0
    try { $fails = [int]$State."FailCount_$Mode" } catch { $fails = 0 }
    if ($fails -gt 0) {
        $sinceFail = Get-SherlogHoursSince -Stamp $State."LastFailUtc_$Mode" -NowUtc $NowUtc
        $wait = [math]::Min([math]::Pow(2, [math]::Min($fails - 1, 16)), $MinHours)
        if ($null -ne $sinceFail -and $sinceFail -lt $wait) {
            return [pscustomobject]@{
                ExitCode = 1
                Message  = "last $fails run(s) failed, next retry in $([math]::Round($wait - $sinceFail, 1))h (backoff; set `$Force = `$true to run now)."
            }
        }
    }
    return $null
}

# ============================================================================
# Main
# ============================================================================

$stateKey = 'HKLM:\SOFTWARE\Sherlog'
$runValue = "LastRunUtc_$CollectionMode"
$failValue = "LastFailUtc_$CollectionMode"
$failCountValue = "FailCount_$CollectionMode"

function Set-SherlogState {
    # Never `New-Item -Force` on an existing registry key: that recreates the
    # key and wipes its other values (the collector's device-label salt).
    param([bool]$Success, [string]$ResultId)
    try {
        if (-not (Test-Path -LiteralPath $stateKey)) { New-Item -Path $stateKey | Out-Null }
        $now = (Get-Date).ToUniversalTime().ToString('o')
        if ($Success) {
            Set-ItemProperty -Path $stateKey -Name $runValue -Value $now
            Set-ItemProperty -Path $stateKey -Name LastResultId -Value $ResultId
            Remove-ItemProperty -Path $stateKey -Name $failValue, $failCountValue -ErrorAction SilentlyContinue
        } else {
            $count = 0
            try { $count = [int](Get-ItemProperty -Path $stateKey -Name $failCountValue -ErrorAction Stop).$failCountValue } catch { $count = 0 }
            Set-ItemProperty -Path $stateKey -Name $failValue -Value $now
            Set-ItemProperty -Path $stateKey -Name $failCountValue -Value ($count + 1)
        }
        # Wrapper <= 1.3 stored the full result URL - a bearer link to the
        # package - in this Users-readable key. Drop it.
        Remove-ItemProperty -Path $stateKey -Name LastResultUrl -ErrorAction SilentlyContinue
    } catch { Write-Verbose "State update failed: $($_.Exception.Message)" }
}

function Exit-Sherlog {
    param([int]$Code, [string]$Message, [switch]$RecordFailure)
    if ($RecordFailure) { Set-SherlogState -Success $false }
    Write-Output ('Sherlog: ' + (Protect-SherlogText -Text $Message -Secret $UploadToken))
    exit $Code
}

# ---- configuration checks ---------------------------------------------------
$SherlogBase = "$SherlogBase".Trim().TrimEnd('/')
if ($SherlogBase -notmatch '^https://[^/\s]+' -and
    $SherlogBase -notmatch '^http://(localhost|127\.0\.0\.1)(:\d+)?(/\S*)?$') {
    Exit-Sherlog 1 'SherlogBase must start with https:// (plain http is only allowed for localhost testing).'
}
if ($UploadToken -eq '<PASTE-YOUR-TOKEN-HERE>' -or "$UploadToken".Length -lt 24) {
    Exit-Sherlog 1 'UploadToken not configured (edit the script settings).'
}
if ($UploadToken -like 'shk_*') {
    Exit-Sherlog 1 'UploadToken is the INBOX KEY (shk_...) - never deploy it to devices; deploy the device upload token (shu_...) from the /inbox page instead.'
}
if ($CollectorSha256 -notmatch '^[0-9A-Fa-f]{64}$') {
    Exit-Sherlog 1 'CollectorSha256 is not set to the collector hash - copy the script again from the /inbox page.'
}
if ($CollectionMode -notin @('full', 'anon')) {
    Exit-Sherlog 1 "CollectionMode must be 'full' or 'anon'."
}

# ---- throttle / failure backoff ---------------------------------------------
if (-not $Force) {
    $state = Get-ItemProperty -Path $stateKey -ErrorAction SilentlyContinue
    $skip = Get-SherlogSkipReason -State $state -Mode $CollectionMode `
                -NowUtc ([DateTime]::UtcNow) -MinHours $MinHoursBetweenRuns
    if ($skip) { Exit-Sherlog $skip.ExitCode $skip.Message }
}

Enable-SherlogTls12

# ---- protected working folder ----------------------------------------------
# %ProgramData% lets standard users create folders, so %ProgramData%\Sherlog
# may have been pre-created (and be owned) by one. Initialize-SherlogDir
# rebuilds the ACL from SIDs and verifies it; every run then works in a fresh,
# random subfolder that must not exist yet, so nothing planted beforehand is
# ever executed or written through.
$root = Join-Path $env:ProgramData 'Sherlog'
if (-not (Initialize-SherlogDir -Path $root)) {
    Exit-Sherlog 1 "could not secure $root (foreign owner/ACL that cannot be removed)." -RecordFailure
}
# Best-effort cleanup of earlier runs that died before their finally block,
# plus the files wrapper <= 1.3 left directly in the root.
try {
    foreach ($old in @(Get-ChildItem -LiteralPath $root -Force -ErrorAction SilentlyContinue)) {
        $stale = ($old.Name -match '^[0-9a-f]{32}$' -and $old.LastWriteTimeUtc -lt [DateTime]::UtcNow.AddHours(-12)) -or
                 $old.Name -eq 'Collect-IntuneDiagnostics.ps1' -or $old.Name -like 'IntuneDiag-*'
        if ($stale) { try { Remove-SherlogTree -Path $old.FullName } catch { Write-Verbose "cleanup: $($_.Exception.Message)" } }
    }
} catch { Write-Verbose "cleanup: $($_.Exception.Message)" }

$runDir = Join-Path $root ([guid]::NewGuid().ToString('N'))
if (-not (Initialize-SherlogDir -Path $runDir -MustBeNew)) {
    Exit-Sherlog 1 'could not create a protected per-run folder.' -RecordFailure
}

$exitCode = 1
$summary = 'unexpected wrapper error.'
try {
    # ---- download + integrity pin ------------------------------------------
    $collector = Join-Path $runDir 'Collect-IntuneDiagnostics.ps1'
    $download = @{
        Uri             = "$SherlogBase/collect-script"
        OutFile         = $collector
        UseBasicParsing = $true
        TimeoutSec      = 120
        ErrorAction     = 'Stop'
    }
    $proxy = Get-SherlogProxy -TargetUrl $SherlogBase
    if ($proxy) {
        $download['Proxy'] = $proxy
        $download['ProxyUseDefaultCredentials'] = $true
    }
    $downloaded = $false
    try {
        Invoke-WebRequest @download
        $downloaded = $true
    } catch {
        $summary = "collector download failed: $($_.Exception.Message)"
    }
    if ($downloaded) {
        $actual = (Get-FileHash -LiteralPath $collector -Algorithm SHA256).Hash
        if ($actual -ne $CollectorSha256) {
            try { Remove-SherlogTree -Path $collector } catch { Write-Verbose 'could not delete the rejected download' }
            $downloaded = $false
            $summary = 'collector hash mismatch (server script changed or download tampered with) - not run; copy the script again from the /inbox page.'
        }
    }

    if ($downloaded) {
        # Splat a HASHTABLE, never an array: array splatting binds every
        # element POSITIONALLY ('-OutputPath' would land in $OutputPath).
        # -Anonymize is driven solely by $CollectionMode (single source of
        # truth); the /inbox generator flips that variable, not this call.
        $collectorArgs = @{
            Remote         = $true
            OutputPath     = $runDir
            UploadUrl      = "$SherlogBase/api/diagnostics"
            UploadToken    = $UploadToken
            WrapperVersion = $WrapperVersion
        }
        if ($CollectionMode -eq 'anon') { $collectorArgs['Anonymize'] = $true }

        # *>&1: Write-Host/Write-Warning/Write-Error of the collector must not
        # reach the (2048-char) Intune output; only the result line is used.
        $records = @()
        $crash = $null
        try {
            $records = @(& $collector @collectorArgs *>&1)
        } catch {
            $crash = $_.Exception.Message
            try { Stop-Transcript -ErrorAction Stop | Out-Null } catch { Write-Verbose 'no transcript to stop' }
        }
        $lines = @(foreach ($rec in $records) { "$rec" })
        $resultLine = $lines | Where-Object { $_ -match '^SHERLOG_(RESULT|ERROR)=' } | Select-Object -Last 1

        if ($resultLine -match '^SHERLOG_RESULT=uploaded id=([0-9a-f]{8})\s*$') {
            $resultId = $matches[1]
            Set-SherlogState -Success $true -ResultId $resultId
            $exitCode = 0
            $summary = "uploaded (id $resultId, mode $CollectionMode, wrapper $WrapperVersion)."
        } elseif ($resultLine -match '^SHERLOG_ERROR=(.*)$') {
            $summary = "collection failed: $($matches[1])"
        } elseif ($crash) {
            $summary = "collection aborted: $crash"
        } else {
            $lastError = $records | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] } | Select-Object -Last 1
            $summary = 'collector produced no result line (nothing uploaded)'
            if ($lastError) { $summary += "; last error: $($lastError.Exception.Message)" }
        }
    }
} catch {
    $summary = "wrapper error: $($_.Exception.Message)"
} finally {
    try { Remove-SherlogTree -Path $runDir } catch { Write-Verbose "could not remove $runDir" }
}

if ($exitCode -ne 0) { Set-SherlogState -Success $false }
Exit-Sherlog $exitCode $summary
