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

    Result: a single zip file in %ProgramData%\Sherlog\Collect (a folder only
    SYSTEM and Administrators can read or write) or in -OutputPath, plus a
    _MANIFEST.json describing the run (version, profile, per-step outcome,
    redaction outcome).

.PARAMETER OutputPath
    Folder where the zip file will be created. Default:
    %ProgramData%\Sherlog\Collect, created with an ACL that only grants
    SYSTEM and Administrators access (a standard user can neither read the
    package nor plant files in it). A custom folder is used as-is; the
    temporary work folder inside it is always locked down the same way.

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
    cleartext (http://localhost and http://127.0.0.1 are allowed for testing).

.PARAMETER UploadToken
    The device UPLOAD token (shu_...) from the Sherlog /inbox page. It only
    authorizes uploads; the INBOX KEY (shk_...) that opens the inbox must
    never be deployed to devices, and the script refuses to run with it.
    The token is always redacted from every collected text file (including
    the transcript, which PowerShell stamps with the full command line it was
    invoked with), regardless of -Anonymize, and the finished zip is scanned
    for it (UTF-8, UTF-16 and base64 forms, binaries included) before upload.

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
    Explicit proxy URL for all outbound calls (e.g. http://proxy.contoso.com:8080).
    If omitted, the machine WinHTTP proxy is used (read from the registry, with
    `netsh winhttp show proxy` as a fallback), since a SYSTEM-context run has no
    per-user WinINET proxy settings and would otherwise fail on any proxy-only
    network.

.PARAMETER Anonymize
    Best-effort redaction of tenant, company, user and device data from the
    package: tenant id/name, company name, domain(s), UPN/e-mail, device name,
    Entra/Intune device ids, user names and profile folder names, user SIDs,
    serial number, Defender org id, Wi-Fi SSIDs and IPv4/IPv6/MAC addresses
    are replaced with placeholders in every file that decodes as text
    (including the UTF-16 hex(2)/hex(7) values in .reg exports), and the zip
    name + upload device name become a salted, non-reversible label.
    Name-like values only match as whole words, so a domain CORP does not
    break "Corporation". Well-known system principals (SYSTEM, NT AUTHORITY,
    ...) are never redacted, since doing so would corrupt registry paths like
    HKEY_LOCAL_MACHINE\SYSTEM\... and break Sherlog's SYSTEM-context detection.
    This is best-effort, NOT a guarantee: binary files (event logs .evtx,
    Defender .cab, the nested mdmdiag .zip, .etl) are NOT scrubbed and may
    still contain identifiers - review the package before sharing. A file
    that cannot be redacted is removed from the package (listed in
    _MANIFEST.json); if redaction fails as a whole, nothing is uploaded.

.PARAMETER WrapperVersion
    Set by the Intune remediation wrapper (Remediate-CollectToSherlog.ps1) so
    the manifest records which wrapper ran the collector.

.EXAMPLE
    .\Collect-IntuneDiagnostics.ps1
    .\Collect-IntuneDiagnostics.ps1 -OutputPath D:\Diag

.EXAMPLE
    # Share-safe, best-effort anonymized package:
    .\Collect-IntuneDiagnostics.ps1 -Remote -Anonymize

.EXAMPLE
    # Unattended drop-off (e.g. from an Intune remediation script):
    .\Collect-IntuneDiagnostics.ps1 -Remote `
        -UploadUrl 'https://sherlog.nl/api/diagnostics' -UploadToken 'shu_...'

.NOTES
    Run as Administrator (elevated PowerShell), or as SYSTEM via Intune.
    Targets Windows PowerShell 5.1.
#>

[CmdletBinding()]
param(
    [string]$OutputPath,
    [switch]$Remote,
    [string]$UploadUrl,
    [string]$UploadToken,
    [int]$MaxUploadMB = 100,
    [string]$Proxy,
    [switch]$Anonymize,
    [string]$WrapperVersion
)

$ScriptVersion = '1.4.0'

# ============================================================================
# Shared helpers. The proxy and folder-ACL functions below are byte-identical
# copies of the ones in Remediate-CollectToSherlog.ps1 (a test enforces this):
# the wrapper is pasted into Intune on its own and cannot dot-source them.
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
# Collector helpers
# ============================================================================

function Test-SherlogSecureUrl {
    param([string]$Url)
    return ($Url -match '^https://[^/\s]+' -or
            $Url -match '^http://(localhost|127\.0\.0\.1)(:\d+)?(/\S*)?$')
}

function Get-SherlogBaseUrl {
    # https://host/api/diagnostics -> https://host (shared by ping and upload).
    param([string]$UploadUrl)
    return ($UploadUrl -replace '/api/diagnostics/?$', '').TrimEnd('/')
}

function Get-SherlogUploadProblem {
    # Single "may this run talk to Sherlog?" check, shared by the status ping
    # and the upload. $null = OK, otherwise the reason.
    param([string]$Url, [string]$Token)
    if (-not $Url) { return 'no -UploadUrl given' }
    if (-not $Token -or $Token -eq '<PASTE-YOUR-TOKEN-HERE>') { return 'UploadUrl set without a real UploadToken' }
    if ($Token -like 'shk_*') {
        return 'the configured token is the INBOX KEY (shk_...) - deploy the device upload token (shu_...) instead'
    }
    if (-not (Test-SherlogSecureUrl -Url $Url)) {
        return 'UploadUrl is not https:// - refusing to send the token in cleartext'
    }
    return $null
}

function Send-SherlogPing {
    # Collection takes minutes; without this the inbox stays empty until the
    # zip lands and the admin cannot tell "still running" from "never started".
    # Best-effort by design: short timeout, no retries, every failure swallowed
    # - a status ping must never break or slow down the collection itself.
    param([ValidateSet('start','failed')][string]$Phase, [string]$Reason)
    if (Get-SherlogUploadProblem -Url $UploadUrl -Token $UploadToken) { return }
    try {
        $base = Get-SherlogBaseUrl -UploadUrl $UploadUrl
        $profileName = if ($Remote) { 'remote' } else { 'full' }
        # The reason is an error string, so treat it as untrusted: never let
        # the token ride along, keep it ASCII (PS 5.1 mangles non-ASCII in
        # -Body) and short - the server caps it again anyway.
        $r = Protect-SherlogText -Text $Reason -Secret $UploadToken -Max 200
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
        $pingProxy = Get-SherlogProxy -TargetUrl $base -Explicit $Proxy
        if ($pingProxy) {
            $pingArgs['Proxy'] = $pingProxy
            $pingArgs['ProxyUseDefaultCredentials'] = $true
        }
        Invoke-RestMethod @pingArgs | Out-Null
    } catch {}
}

function Write-SherlogFailure {
    # Every path on which the run knows it failed: one machine-readable line
    # for automation (the remediation wrapper) plus a failed ping for the inbox.
    param([string]$Reason)
    $r = Protect-SherlogText -Text $Reason -Secret $UploadToken -Max 300
    Write-Warning $r
    Write-Output "SHERLOG_ERROR=$r"
    Send-SherlogPing -Phase failed -Reason $r
}

function Invoke-SherlogNative {
    # Windows PowerShell 5.1 turns every stderr line of a native command into
    # an ErrorRecord once stderr is redirected, and Invoke-Safe runs with
    # $ErrorActionPreference = 'Stop' - so harmless stderr noise (wevtutil,
    # powercfg, reg, schtasks) would fail the whole step. Run with a local
    # 'Continue', drop stderr, and let the caller judge $LASTEXITCODE.
    param([Parameter(Mandatory = $true)][string]$FilePath, [string[]]$ArgumentList = @())
    $ErrorActionPreference = 'Continue'
    & $FilePath @ArgumentList 2>$null
}

function Get-DsregField {
    # One "Name : value" field from `dsregcmd /status` output ('' if absent).
    param([string[]]$Lines, [string]$Name)
    $re = '^\s*' + [regex]::Escape($Name) + '\s*:\s*(.+?)\s*$'
    foreach ($line in $Lines) {
        if ($line -match $re) { return $matches[1] }
    }
    return ''
}

function Get-SherlogDeviceSalt {
    # Random per-device salt for the anonymized device label, created once in
    # HKLM\SOFTWARE\Sherlog (64-bit view) and locked to SYSTEM/Administrators.
    # Without a salt the label (a hash of the host name) is brute-forceable
    # from a list of likely host names.
    $system = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
    $admins = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
    $hive = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,
                                                     [Microsoft.Win32.RegistryView]::Registry64)
    try {
        $created = $hive.CreateSubKey('SOFTWARE\Sherlog')
        $created.Close()
        $key = $hive.OpenSubKey('SOFTWARE\Sherlog',
                                [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
                                [System.Security.AccessControl.RegistryRights]::FullControl)
        try {
            try {
                $security = New-Object System.Security.AccessControl.RegistrySecurity
                $security.SetAccessRuleProtection($true, $false)
                $security.SetOwner($admins)
                foreach ($sid in @($system, $admins)) {
                    $rule = New-Object System.Security.AccessControl.RegistryAccessRule(
                        $sid, 'FullControl', 'ContainerInherit', 'None', 'Allow')
                    $security.AddAccessRule($rule)
                }
                $key.SetAccessControl($security)
            } catch { Write-Verbose "Could not lock HKLM\SOFTWARE\Sherlog: $($_.Exception.Message)" }
            $salt = $key.GetValue('DeviceLabelSalt') -as [byte[]]
            if (-not $salt -or $salt.Length -lt 16) {
                $salt = New-Object byte[] 32
                $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
                try { $rng.GetBytes($salt) } finally { $rng.Dispose() }
                $key.SetValue('DeviceLabelSalt', $salt, [Microsoft.Win32.RegistryValueKind]::Binary)
            }
            return , $salt
        } finally { $key.Close() }
    } finally { $hive.Close() }
}

function Get-SherlogAnonLabel {
    # 'anon-' + first 8 bytes of HMAC-SHA256(salt, HOSTNAME): stable per
    # device, not reversible without the device-local salt.
    param([string]$ComputerName, [byte[]]$Salt)
    $hmac = New-Object System.Security.Cryptography.HMACSHA256 -ArgumentList (, $Salt)
    try {
        $hash = $hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes("$ComputerName".ToUpperInvariant()))
    } finally { $hmac.Dispose() }
    return 'anon-' + (-join ($hash[0..7] | ForEach-Object { $_.ToString('x2') }))
}

function Copy-SherlogFile {
    # Copies one file, creating the target folder. IME keeps its current log
    # open for writing; File.Copy can fail on that, so fall back to a stream
    # copy that shares read/write/delete with the writer.
    param([Parameter(Mandatory = $true)][string]$Source, [Parameter(Mandatory = $true)][string]$Destination)
    $dir = [IO.Path]::GetDirectoryName($Destination)
    if (-not [IO.Directory]::Exists($dir)) { [void][IO.Directory]::CreateDirectory($dir) }
    try {
        [IO.File]::Copy($Source, $Destination, $true)
    } catch {
        $share = [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete
        $in = New-Object IO.FileStream($Source, [IO.FileMode]::Open, [IO.FileAccess]::Read, $share)
        try {
            $out = [IO.File]::Create($Destination)
            try { $in.CopyTo($out) } finally { $out.Dispose() }
        } finally { $in.Dispose() }
    }
}

function Test-SherlogEndpoint {
    # Reachability of HOST:443 for every endpoint, in parallel with one shared
    # deadline (Test-NetConnection takes up to ~20 s per dead host, minutes
    # for the whole list). Direct: a TCP connect. With a proxy the device
    # cannot connect directly by design, so test what the IME actually does:
    # an HTTPS request through the proxy (any HTTP answer except the proxy's
    # own 407 counts as reachable).
    param([string[]]$Endpoints, [string]$ProxyUrl, [int]$TimeoutMs = 3000)
    $deadline = [DateTime]::UtcNow.AddMilliseconds($TimeoutMs)
    $rows = New-Object System.Collections.Generic.List[object]
    if ($ProxyUrl) {
        if ([Net.ServicePointManager]::DefaultConnectionLimit -lt 32) {
            [Net.ServicePointManager]::DefaultConnectionLimit = 32
        }
        $probes = foreach ($ep in $Endpoints) {
            $req = $null
            $task = $null
            try {
                $req = [Net.HttpWebRequest]::Create("https://$ep/")
                $req.Method = 'HEAD'
                $req.AllowAutoRedirect = $false
                $req.Timeout = $TimeoutMs
                $webProxy = New-Object System.Net.WebProxy($ProxyUrl)
                $webProxy.UseDefaultCredentials = $true
                $req.Proxy = $webProxy
                $task = $req.GetResponseAsync()
            } catch { $task = $null }
            [pscustomobject]@{ Endpoint = $ep; Request = $req; Task = $task }
        }
        foreach ($p in $probes) {
            $ok = $false
            if ($p.Task) {
                $left = [int][math]::Max(0, ($deadline - [DateTime]::UtcNow).TotalMilliseconds)
                try { [void]$p.Task.Wait($left) } catch { Write-Verbose "$($p.Endpoint): $($_.Exception.Message)" }
                if ($p.Task.Status -eq 'RanToCompletion') {
                    $ok = $true
                    try { $p.Task.Result.Close() } catch { Write-Verbose 'close failed' }
                } elseif ($p.Task.IsFaulted) {
                    $webError = $p.Task.Exception.InnerException
                    if ($webError -is [Net.WebException] -and $webError.Response) {
                        $code = 0
                        try { $code = [int]$webError.Response.StatusCode } catch { $code = 0 }
                        $ok = ($code -ne 407)
                        try { $webError.Response.Close() } catch { Write-Verbose 'close failed' }
                    }
                } else {
                    try { $p.Request.Abort() } catch { Write-Verbose 'abort failed' }
                }
            }
            $rows.Add([pscustomobject]@{ Endpoint = $p.Endpoint; Reachable = $ok
                                         RemoteIP = 'via-proxy'; Method = 'https-via-proxy' })
        }
    } else {
        $probes = foreach ($ep in $Endpoints) {
            $client = New-Object System.Net.Sockets.TcpClient
            $task = $null
            try { $task = $client.ConnectAsync($ep, 443) } catch { $task = $null }
            [pscustomobject]@{ Endpoint = $ep; Client = $client; Task = $task }
        }
        foreach ($p in $probes) {
            $ok = $false
            $ip = ''
            if ($p.Task) {
                $left = [int][math]::Max(0, ($deadline - [DateTime]::UtcNow).TotalMilliseconds)
                try { $ok = $p.Task.Wait($left) } catch { $ok = $false }
                if ($ok -and $p.Client.Connected) {
                    try { $ip = $p.Client.Client.RemoteEndPoint.Address.ToString() } catch { $ip = '' }
                } else {
                    $ok = $false
                }
            }
            try { $p.Client.Close() } catch { Write-Verbose 'close failed' }
            $rows.Add([pscustomobject]@{ Endpoint = $p.Endpoint; Reachable = $ok
                                         RemoteIP = $ip; Method = 'tcp-443' })
        }
    }
    return $rows
}

# ---- redaction ----------------------------------------------------------------

function Add-SherlogRedactToken {
    # Adds a value to the redaction map unless it is too short or a
    # well-known, non-identifying principal/placeholder. Principals like
    # SYSTEM/NT AUTHORITY must never be redacted: that corrupts registry paths
    # like HKEY_LOCAL_MACHINE\SYSTEM\... and breaks the server's
    # SYSTEM-context detection for the Entra PRT check. Generic values
    # ("User", "Owner", "Admin") would only damage text and identify nobody.
    param([System.Collections.Generic.List[object]]$Map, [object]$Value, [string]$Tag)
    if ($null -eq $Value) { return }
    $v = "$Value".Trim()
    if ($v.Length -lt 4) { return }
    $wellKnown = '(?i)^(NT AUTHORITY\\SYSTEM|SYSTEM|NT AUTHORITY|LOCAL SERVICE|NETWORK SERVICE|' +
                 'NT AUTHORITY\\LOCAL SERVICE|NT AUTHORITY\\NETWORK SERVICE|WORKGROUP|Unknown|N/A|None|' +
                 'AzureAD|BUILTIN|User|Users|Owner|Windows User|Admin|Administrator|Administrators|' +
                 'Guest|Public|Default|Default User|All Users|defaultuser\d+|Microsoft|Windows|' +
                 'localhost|To be filled by O\.E\.M\.|Default string|System Serial Number|Not Specified|0+)$'
    if ($v -match $wellKnown) { return }
    $Map.Add([pscustomobject]@{ Value = $v; Tag = $Tag })
}

function Add-SherlogAccountToken {
    # 'DOMAIN\user', 'user@domain' or a machine account 'DOMAIN\PC01$':
    # redact the parts separately (each as a whole word) and keep a machine
    # account's trailing '$', which Sherlog's SYSTEM-context detection keys on.
    param([System.Collections.Generic.List[object]]$Map, [string]$Account)
    $a = "$Account".Trim()
    if (-not $a) { return }
    if ($a -match '^[^@\s\\]+@([^@\s]+)$') {
        Add-SherlogRedactToken -Map $Map -Value $a -Tag '<UPN>'
        Add-SherlogRedactToken -Map $Map -Value $matches[1] -Tag '<DOMAIN>'
        return
    }
    $name = $a
    if ($a -match '^([^\\]+)\\(.+)$') {
        Add-SherlogRedactToken -Map $Map -Value $matches[1] -Tag '<DOMAIN>'
        $name = $matches[2]
    }
    if ($name.EndsWith('$')) {
        Add-SherlogRedactToken -Map $Map -Value $name.TrimEnd('$') -Tag '<DEVICE>'
    } else {
        Add-SherlogRedactToken -Map $Map -Value $name -Tag '<USER>'
    }
}

function ConvertTo-SherlogJsonEscaped {
    # How Windows PowerShell 5.1's ConvertTo-Json writes a string: \ doubled,
    # ' < > & as \u0027 \u003c \u003e \u0026 - a literal token would miss it.
    param([string]$Value)
    return $Value.Replace('\', '\\').Replace("'", '\u0027').Replace('<', '\u003c').Replace('>', '\u003e').Replace('&', '\u0026')
}

function ConvertTo-SherlogRegHex {
    # String -> the UTF-16LE byte list `reg export` writes for hex(2)/hex(7).
    param([string]$Value)
    return (@([Text.Encoding]::Unicode.GetBytes($Value) | ForEach-Object { $_.ToString('x2') }) -join ',')
}

function ConvertTo-SherlogRegHexPattern {
    # Regex for a value inside a .reg hex(2)/hex(7) (REG_EXPAND_SZ /
    # REG_MULTI_SZ) byte list: UTF-16LE bytes "43,00,4f,00,...", either case
    # of every letter, and the ",\" + CRLF + indent line wrap reg.exe inserts
    # after ~80 columns, which can fall between any two bytes. -Bounded adds
    # the whole-word rule of the plain-text form: the neighbouring UTF-16
    # characters must not be ASCII letters/digits.
    param([string]$Value, [switch]$Bounded)
    $sep = ',(?:\\\r?\n[ \t]*)?'
    $alnum = '(?:3[0-9]|4[1-9a-f]|5[0-9a]|6[1-9a-f]|7[0-9a])'
    $parts = foreach ($ch in $Value.ToCharArray()) {
        $upper = ([string]$ch).ToUpperInvariant()
        $lower = ([string]$ch).ToLowerInvariant()
        $alts = @($upper)
        if ($lower -cne $upper) { $alts += $lower }
        $hex = @(foreach ($variant in $alts) {
            (@([Text.Encoding]::Unicode.GetBytes($variant) | ForEach-Object { $_.ToString('x2') }) -join $sep)
        })
        if ($hex.Count -eq 1) { $hex[0] } else { '(?:' + ($hex -join '|') + ')' }
    }
    $pattern = $parts -join $sep
    if ($Bounded) {
        $pattern = '(?<!' + $alnum + $sep + '00' + $sep + ')' + $pattern + '(?!' + $sep + $alnum + $sep + '00)'
    }
    return $pattern
}

function Get-SherlogBase64Core {
    # The stable middle of every base64 rendering of a secret (UTF-8 and
    # UTF-16LE, all three byte alignments): IME logs can carry script bodies
    # base64-encoded, and the remediation wrapper embeds the token.
    param([string]$Secret)
    foreach ($bytes in @(, [Text.Encoding]::UTF8.GetBytes($Secret)) + @(, [Text.Encoding]::Unicode.GetBytes($Secret))) {
        foreach ($k in 0..2) {
            $buffer = New-Object byte[] ($k + $bytes.Length)
            [Array]::Copy($bytes, 0, $buffer, $k, $bytes.Length)
            $b64 = [Convert]::ToBase64String($buffer)
            $first = 0
            if ($k -gt 0) { $first = 1 }
            $last = [math]::Floor(($k + $bytes.Length) / 3) - 1
            if ($last -ge $first) { $b64.Substring(4 * $first, 4 * ($last - $first + 1)) }
        }
    }
}

function New-SherlogRedactionContext {
    # Compiles the redaction rules once for the whole package (the map is
    # small, the file set is not).
    param([object[]]$Map = @(), [switch]$Anonymize)
    $opts = [Text.RegularExpressions.RegexOptions]'IgnoreCase, Compiled, CultureInvariant'
    # Name-like values are only replaced as whole words: USERDOMAIN=CORP must
    # not turn "Corporation" into "<DOMAIN>oration", user "admin" must not hit
    # "Administrators", RegisteredOwner "Owner" not "RunAsOwner".
    $nameTags = @('<DEVICE>', '<USER>', '<DOMAIN>', '<COMPANY>', '<TENANT>', '<SSID>', '<SERIAL>')
    $rules = New-Object System.Collections.Generic.List[object]
    $seen = @{}
    foreach ($entry in @($Map | Where-Object { $_ -and $_.Value } | Sort-Object { $_.Value.Length } -Descending)) {
        $key = $entry.Value.ToLowerInvariant()
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true
        $bounded = $nameTags -contains $entry.Tag
        $variants = @($entry.Value)
        $json = ConvertTo-SherlogJsonEscaped -Value $entry.Value
        if ($json -cne $entry.Value) { $variants += $json }
        foreach ($v in $variants) {
            $lit = [regex]::Escape($v)
            # Boundaries (?<![A-Za-z0-9]) + literal + (?![A-Za-z0-9]), with the
            # lookbehind moved after the literal: .NET Framework's regex engine
            # only skips ahead fast on a *leading* literal (same reason the
            # e-mail pattern starts with '@').
            if ($bounded) { $pattern = $lit + '(?<![A-Za-z0-9]' + $lit + ')(?![A-Za-z0-9])' } else { $pattern = $lit }
            $rules.Add([pscustomobject]@{ Re = [regex]::new($pattern, $opts); Tag = $entry.Tag; RegOnly = $false })
        }
        $rules.Add([pscustomobject]@{
            Re = [regex]::new((ConvertTo-SherlogRegHexPattern -Value $entry.Value -Bounded:$bounded), $opts)
            Tag = (ConvertTo-SherlogRegHex -Value $entry.Tag); RegOnly = $true })
        if ($entry.Tag -eq '<UPLOAD-TOKEN>') {
            foreach ($core in @(Get-SherlogBase64Core -Secret $entry.Value)) {
                # Same-length, base64-safe filler keeps the blob decodable.
                $filler = ('REDACTED' * [int][math]::Ceiling($core.Length / 8)).Substring(0, $core.Length)
                $rules.Add([pscustomobject]@{
                    Re = [regex]::new([regex]::Escape($core), [Text.RegularExpressions.RegexOptions]'Compiled, CultureInvariant')
                    Tag = $filler; RegOnly = $false })
            }
        }
    }

    # E-mail catch-all, anchored on the literal '@' so the engine can skip
    # through a multi-MB IME log at native speed. A pattern that starts with
    # the local part instead tries - and backtracks out of - every GUID, hash
    # and base64 run in the file; that is what made -Anonymize run for
    # minutes on log-heavy devices. The local part is walked backwards from
    # the match, bounded by its own length.
    $emailRe = [regex]::new('@[A-Z0-9.-]+\.[A-Z]{2,}', $opts)
    $isLocal = New-Object 'bool[]' 128
    foreach ($c in [char[]]'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._%+-') {
        $isLocal[[int]$c] = $true
    }
    $octet = '(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)'
    $patterns = @(
        # Domain/local user SIDs and Entra ID user SIDs (S-1-12-1-...).
        [pscustomobject]@{ Tag = '<SID>'; Re = [regex]::new(
            'S-1-(?:5-21-\d{1,10}-\d{1,10}-\d{1,10}(?:-\d{1,10})?|12-1-\d{1,10}-\d{1,10}-\d{1,10}-\d{1,10})(?!\d)', $opts) }
        [pscustomobject]@{ Tag = '<MAC>'; Re = [regex]::new(
            '(?<![0-9A-F:-])[0-9A-F]{2}([:-])[0-9A-F]{2}(?:\1[0-9A-F]{2}){4}(?![0-9A-F:-])', $opts) }
        # Full 8-group or '::'-compressed IPv6 with at least one digit; never
        # matches hh:mm:ss times (no '::', fewer than 8 groups).
        [pscustomobject]@{ Tag = '<IPV6>'; Re = [regex]::new(
            '(?<![\w:.\]])(?=[0-9A-F:]*\d)(?:(?:[0-9A-F]{1,4}:){7}[0-9A-F]{1,4}|(?:[0-9A-F]{1,4}:){1,6}(?::[0-9A-F]{1,4}){1,6}|(?:[0-9A-F]{1,4}:){1,7}:)(?:%\w+)?(?![\w:])', $opts) }
        # IPv4, except non-identifying ones (0.0.0.0, loopback, masks,
        # link-local, multicast) and dotted-quad VERSION numbers ("Version
        # 1.0.0.0", "DisplayVersion"="10.2.3.4") that IME logs are full of.
        [pscustomobject]@{ Tag = '<IPV4>'; Re = [regex]::new(
            '(?<![\w.])(?<!ver[a-z]{0,8}[\s:="''>(]{0,4})(?!0\.0\.0\.0(?![\w.])|127\.|255\.|169\.254\.|22[4-9]\.|23\d\.)(?:' +
            $octet + '\.){3}' + $octet + '(?!\w|\.\d)', $opts) }
    )
    return [pscustomobject]@{
        Rules = $rules; Anonymize = [bool]$Anonymize; Email = $emailRe; IsLocal = $isLocal
        Patterns = $patterns; Values = $seen.Count
    }
}

function Hide-SherlogEmail {
    param([string]$Text, $Context)
    if ($Text.IndexOf('@') -lt 0) { return $Text }
    $isLocal = $Context.IsLocal
    $sb = New-Object Text.StringBuilder($Text.Length)
    $pos = 0
    foreach ($m in $Context.Email.Matches($Text)) {
        if ($m.Index -lt $pos) { continue }
        $s = $m.Index
        while ($s -gt $pos -and [int]$Text[$s - 1] -lt 128 -and $isLocal[[int]$Text[$s - 1]]) { $s-- }
        if ($s -eq $m.Index) { continue }   # bare '@domain' is not an address
        [void]$sb.Append($Text, $pos, $s - $pos).Append('<EMAIL>')
        $pos = $m.Index + $m.Length
    }
    if ($pos -eq 0) { return $Text }
    [void]$sb.Append($Text, $pos, $Text.Length - $pos)
    return $sb.ToString()
}

function Invoke-SherlogStringRedaction {
    param([string]$Text, [Parameter(Mandatory = $true)]$Context, [switch]$IsReg)
    $text = "$Text"
    foreach ($r in $Context.Rules) {
        if ($r.RegOnly -and -not $IsReg) { continue }
        # IsMatch first: Replace copies the whole (multi-MB) string even when
        # nothing matches, and most tokens appear in only a handful of files.
        if ($r.Re.IsMatch($text)) { $text = $r.Re.Replace($text, $r.Tag) }
    }
    if ($Context.Anonymize) {
        $text = Hide-SherlogEmail -Text $text -Context $Context
        foreach ($p in $Context.Patterns) {
            if ($p.Re.IsMatch($text)) { $text = $p.Re.Replace($text, $p.Tag) }
        }
    }
    return $text
}

function Get-SherlogTextEncoding {
    # Decides how to decode a file for redaction, by content rather than by
    # extension: BOM first, then UTF-16LE without BOM (NUL in every odd byte),
    # other NUL-bearing content is binary ($null), then strict UTF-8 with a
    # lossless Latin-1 fallback for ANSI text (a non-strict UTF-8 round trip
    # would replace every invalid byte with U+FFFD and corrupt the file).
    param([byte[]]$Bytes)
    $n = $Bytes.Length
    if ($n -ge 3 -and $Bytes[0] -eq 0xEF -and $Bytes[1] -eq 0xBB -and $Bytes[2] -eq 0xBF) {
        return (New-Object Text.UTF8Encoding($true))
    }
    if ($n -ge 2 -and $Bytes[0] -eq 0xFF -and $Bytes[1] -eq 0xFE) { return [Text.Encoding]::Unicode }
    if ($n -ge 2 -and $Bytes[0] -eq 0xFE -and $Bytes[1] -eq 0xFF) { return [Text.Encoding]::BigEndianUnicode }
    $probe = [math]::Min($n, 8192)
    if ($probe -gt 0 -and [Array]::IndexOf($Bytes, [byte]0, 0, $probe) -ge 0) {
        $zeroOdd = 0
        $zeroEven = 0
        for ($i = 0; $i -lt $probe; $i++) {
            if ($Bytes[$i] -eq 0) { if ($i % 2) { $zeroOdd++ } else { $zeroEven++ } }
        }
        if ($zeroOdd -ge [math]::Floor($probe / 2) * 0.6 -and $zeroEven -le $probe / 100) {
            return (New-Object Text.UnicodeEncoding($false, $false))
        }
        return $null
    }
    $strict = New-Object Text.UTF8Encoding($false, $true)
    try {
        [void]$strict.GetCharCount($Bytes)
        return $strict
    } catch {
        return [Text.Encoding]::GetEncoding(28591)
    }
}

function Invoke-TextRedaction {
    # One pass over the package. Fails CLOSED: a file that cannot be read,
    # decoded or rewritten is deleted from the package and listed; only if
    # even that fails does the function throw (and the caller must not upload).
    param([Parameter(Mandatory = $true)][string]$Root, [Parameter(Mandatory = $true)]$Context)
    $binaryExt = @('.evtx', '.cab', '.zip', '.etl', '.dat', '.bin')
    $result = [pscustomobject]@{
        Scanned = 0; Changed = 0; Binary = 0
        Removed = (New-Object System.Collections.Generic.List[string])
    }
    $rootFull = [IO.Path]::GetFullPath($Root).TrimEnd('\', '/')
    foreach ($f in @(Get-ChildItem -LiteralPath $Root -Recurse -File -Force)) {
        $ext = $f.Extension.ToLowerInvariant()
        if ($binaryExt -contains $ext) { $result.Binary++; continue }
        $rel = $f.FullName.Substring($rootFull.Length).TrimStart('\', '/')
        try {
            $bytes = [IO.File]::ReadAllBytes($f.FullName)
            $enc = Get-SherlogTextEncoding -Bytes $bytes
            if ($null -eq $enc) { $result.Binary++; continue }
            $result.Scanned++
            $text = $enc.GetString($bytes)
            if ($text.Length -gt 0 -and $text[0] -eq [char]0xFEFF) { $text = $text.Substring(1) }
            $new = Invoke-SherlogStringRedaction -Text $text -Context $Context -IsReg:($ext -eq '.reg')
            if (-not [string]::Equals($new, $text, [StringComparison]::Ordinal)) {
                # WriteAllText writes the preamble for BOM encodings and none
                # for UTF8Encoding($false)/Latin-1, i.e. the original layout.
                [IO.File]::WriteAllText($f.FullName, $new, $enc)
                $result.Changed++
            }
        } catch {
            $why = $_.Exception.Message
            try {
                [IO.File]::Delete($f.FullName)
            } catch {
                throw "could not redact '$rel' ($why) and could not remove it: $($_.Exception.Message)"
            }
            Write-Warning "  Could not redact $rel ($why); removed it from the package."
            $result.Removed.Add($rel)
        }
    }
    return $result
}

# ---- package secret scan ------------------------------------------------------

function Test-SherlogStreamHasNeedle {
    # Streams bytes as Latin-1 (1 byte = 1 char, lossless) so a native
    # String.IndexOf can look for byte patterns; chunks overlap by the longest
    # needle so a hit on a chunk boundary is not missed.
    param([Parameter(Mandatory = $true)][IO.Stream]$Stream, [Parameter(Mandatory = $true)][string[]]$Needles)
    $latin1 = [Text.Encoding]::GetEncoding(28591)
    $maxLen = ($Needles | Measure-Object -Property Length -Maximum).Maximum
    $buffer = New-Object byte[] 1048576
    $carry = ''
    while (($read = $Stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
        $chunk = $carry + $latin1.GetString($buffer, 0, $read)
        foreach ($needle in $Needles) {
            if ($chunk.IndexOf($needle, [StringComparison]::OrdinalIgnoreCase) -ge 0) { return $true }
        }
        $keep = [math]::Min($chunk.Length, $maxLen - 1)
        $carry = $chunk.Substring($chunk.Length - $keep)
    }
    return $false
}

function Find-SherlogSecretInZipStream {
    param([IO.Stream]$Stream, [string[]]$Needles, [string]$Prefix, [int]$Depth)
    $zip = New-Object IO.Compression.ZipArchive($Stream, [IO.Compression.ZipArchiveMode]::Read, $true)
    try {
        foreach ($entry in $zip.Entries) {
            $name = $Prefix + $entry.FullName
            $s = $entry.Open()
            try {
                if (Test-SherlogStreamHasNeedle -Stream $s -Needles $Needles) { return $name }
            } finally { $s.Dispose() }
            if ($Depth -lt 1 -and $entry.FullName -match '\.zip$') {
                # One nested level (the mdmdiagnosticstool zip): its entries
                # are compressed, so the raw bytes above prove nothing.
                $ms = New-Object IO.MemoryStream
                try {
                    $s = $entry.Open()
                    try { $s.CopyTo($ms) } finally { $s.Dispose() }
                    $ms.Position = 0
                    $hit = $null
                    try {
                        $hit = Find-SherlogSecretInZipStream -Stream $ms -Needles $Needles -Prefix "$name!/" -Depth ($Depth + 1)
                    } catch {
                        $hit = "$name (nested zip could not be verified)"
                    }
                    if ($hit) { return $hit }
                } finally { $ms.Dispose() }
            }
        }
    } finally { $zip.Dispose() }
    return $null
}

function Find-SherlogSecretInZip {
    # Last line of defence before upload: every entry of the finished zip
    # (binaries included) is searched for the secret as UTF-8, UTF-16LE and
    # base64. Returns the first entry that contains it, else $null.
    param([Parameter(Mandatory = $true)][string]$ZipPath, [Parameter(Mandatory = $true)][string]$Secret)
    Add-Type -AssemblyName System.IO.Compression -ErrorAction SilentlyContinue
    $latin1 = [Text.Encoding]::GetEncoding(28591)
    $needles = @($latin1.GetString([Text.Encoding]::UTF8.GetBytes($Secret)),
                 $latin1.GetString([Text.Encoding]::Unicode.GetBytes($Secret))) +
               @(Get-SherlogBase64Core -Secret $Secret)
    $fs = [IO.File]::OpenRead($ZipPath)
    try {
        return (Find-SherlogSecretInZipStream -Stream $fs -Needles $needles -Prefix '' -Depth 0)
    } finally { $fs.Dispose() }
}

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

# The inbox key opens every package in the inbox; it must never sit on a
# device (or in this run's transcript). Refuse before collecting anything.
if ($UploadToken -like 'shk_*') {
    Write-SherlogFailure 'UploadToken is the INBOX KEY (shk_...) - deploy the device upload token (shu_...) instead; nothing collected'
    exit 1
}

# 32-bit PowerShell on 64-bit Windows sees SysWOW64 as System32 (no
# mdmdiagnosticstool there, 32-bit reg.exe); Sysnative reaches the real one.
$sys32 = Join-Path $env:windir 'System32'
if (-not [Environment]::Is64BitProcess -and [Environment]::Is64BitOperatingSystem) {
    $sys32 = Join-Path $env:windir 'Sysnative'
    Write-Warning 'Running in 32-bit PowerShell on a 64-bit OS; using Sysnative tools. Prefer 64-bit PowerShell.'
}
if ($ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') {
    Write-Warning "PowerShell is running in $($ExecutionContext.SessionState.LanguageMode) mode; some collection steps (JSON export, .NET types) may fail under WDAC/CLM restrictions."
}

# .NET-formatted output (event level names, error messages) follows this
# thread culture; native console tools (netsh, certutil) still follow the OS
# display language regardless and are NOT made English by this.
try {
    [Threading.Thread]::CurrentThread.CurrentUICulture = [Globalization.CultureInfo]::GetCultureInfo('en-US')
    [Threading.Thread]::CurrentThread.CurrentCulture    = [Globalization.CultureInfo]::GetCultureInfo('en-US')
} catch { Write-Verbose 'Could not switch the thread culture.' }

$ProgressPreference = 'SilentlyContinue'  # large -InFile uploads/copies stay fast on PS 5.1
$PSDefaultParameterValues['Out-File:Encoding'] = 'utf8'
# Format-List/Format-Table output is wrapped at the console width (80 when
# there is no console, e.g. under SYSTEM) - a wrapped value can split a
# token across lines and slip past redaction, and it breaks the parsers.
$PSDefaultParameterValues['Out-File:Width'] = 4096

$startedUtc = [DateTime]::UtcNow
$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
# Device label for the zip name and upload header. With -Anonymize it is a
# salted HMAC of the computer name (see Get-SherlogDeviceSalt), so the
# filename and inbox don't leak the hostname and it cannot be brute-forced.
$deviceLabel = $env:COMPUTERNAME
if ($Anonymize) {
    $salt = $null
    try { $salt = Get-SherlogDeviceSalt } catch { $salt = $null }
    if (-not $salt) {
        Write-Warning 'Could not store a device salt; the anonymized label will differ per run.'
        $salt = New-Object byte[] 32
        $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        try { $rng.GetBytes($salt) } finally { $rng.Dispose() }
    }
    $deviceLabel = Get-SherlogAnonLabel -ComputerName $env:COMPUTERNAME -Salt $salt
}

Enable-SherlogTls12

# Output folder. The old default (a Temp folder on C:) is writable by every user: they
# could read the package or plant files/links in it. The default is now a
# SYSTEM/Administrators-only folder, verified by SID-based ACL checks.
if (-not $OutputPath) {
    $OutputPath = Join-Path $env:ProgramData 'Sherlog\Collect'
    if (-not (Initialize-SherlogDir -Path (Join-Path $env:ProgramData 'Sherlog')) -or
        -not (Initialize-SherlogDir -Path $OutputPath)) {
        Write-SherlogFailure "could not create the protected output folder $OutputPath"
        exit 1
    }
} elseif (-not (Test-Path -LiteralPath $OutputPath -PathType Container)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

try {
    $driveLetter = $OutputPath.Substring(0, 1)
    $vol = Get-Volume -DriveLetter $driveLetter -ErrorAction Stop
    if ($vol.SizeRemaining -lt 500MB) {
        Write-Warning "Less than 500 MB free on ${driveLetter}: - collection may fail."
    }
} catch { Write-Verbose 'Free-space check skipped.' }

# The work folder must be new (never reuse something that was waiting at a
# predictable path) and is locked to SYSTEM/Administrators even when
# -OutputPath itself is a shared folder.
$work = Join-Path $OutputPath "IntuneDiag-$deviceLabel-$timestamp"
if (Test-Path -LiteralPath $work) { $work += '-' + [guid]::NewGuid().ToString('N').Substring(0, 6) }
if (-not (Initialize-SherlogDir -Path $work -MustBeNew)) {
    Write-SherlogFailure "could not create a protected work folder under $OutputPath"
    exit 1
}
$zipFile   = "$work.zip"

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
$dsregLines = @()

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
    $mdmTool = Join-Path $sys32 'mdmdiagnosticstool.exe'
    # The all-areas zip duplicates the event logs and registry exports below
    # and is the single largest item in the package; skip it in the slim
    # remote profile and keep only the small default report.
    if (-not $Remote) {
        $areaKey = 'HKLM:\SOFTWARE\Microsoft\MdmDiagnostics\Area'
        if (Test-Path $areaKey) {
            $areas = (Get-ChildItem $areaKey).PSChildName -join ';'
            Write-Host "  Areas found: $areas"
            Invoke-SherlogNative $mdmTool @('-area', $areas, '-zip', (Join-Path $work 'MDM\MDMDiag-AllAreas.zip')) | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "mdmdiagnosticstool -area exited with code $LASTEXITCODE" }
        }
    }
    Invoke-SherlogNative $mdmTool @('-out', (Join-Path $work 'MDM\DefaultReport')) | Out-Null
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
        $wevtutil = Join-Path $sys32 'wevtutil.exe'
        if ($Remote) {
            # Slim profile: only the last N days in the raw export too - the
            # biggest single size contributor on a chatty Application/System log.
            $q = "*[System[TimeCreated[timediff(@SystemTime) <= $($eventLogWindowDays * 86400000)]]]"
            Invoke-SherlogNative $wevtutil @('epl', $entry.Value, $dest, "/q:$q", '/ow:true') | Out-Null
        } else {
            Invoke-SherlogNative $wevtutil @('epl', $entry.Value, $dest, '/ow:true') | Out-Null
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
                Format-List | Out-File (Join-Path $work "EventLogs\$($entry.Key)-ErrorsWarnings.txt")
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
# /reg:64: a 32-bit host would otherwise export the WOW6432Node view, where
# most of these keys do not exist.
$regView = @()
if ([Environment]::Is64BitOperatingSystem) { $regView = @('/reg:64') }

foreach ($entry in $regKeys.GetEnumerator()) {
    Invoke-Safe "Registry: $($entry.Key)..." {
        $regArgs = @('export', $entry.Value, (Join-Path $work "Registry\$($entry.Key).reg"), '/y') + $regView
        Invoke-SherlogNative (Join-Path $sys32 'reg.exe') $regArgs | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "reg export exited with code $LASTEXITCODE (key may not exist on this device)" }
    }
}

# ============================================================
# 4. Identity & certificates
# ============================================================
Invoke-Safe 'dsregcmd /status (machine/SYSTEM context)...' {
    $script:dsregLines = @(Invoke-SherlogNative (Join-Path $sys32 'dsregcmd.exe') @('/status'))
    $script:dsregLines | Out-File (Join-Path $work 'Identity\dsregcmd-status.txt')
    if ($script:dsregLines.Count -eq 0) { throw "dsregcmd /status produced no output (exit code $LASTEXITCODE)" }
}

# The Primary Refresh Token is per-user: dsregcmd run as SYSTEM (the usual
# Intune remediation context) can never see it. Best-effort: run dsregcmd as
# the interactively logged-on user via a one-shot scheduled task, so the PRT
# check has a real signal instead of always reading "unknown".
# - Register-ScheduledTask with an Interactive/Limited principal needs no
#   password (schtasks /RU without /RP prompts for one and hangs/fails).
# - The task runs as that LIMITED user, so it can't write into the
#   SYSTEM/Admins-only work folder: SYSTEM pre-creates one output file in a
#   dedicated folder and grants only that user (by SID) Modify on that file.
# - Completion is read from Get-ScheduledTaskInfo.LastTaskResult (numeric,
#   locale-independent) instead of parsing localized schtasks text.
Invoke-Safe 'dsregcmd /status (interactive user context)...' {
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    $userName = $cs.UserName
    if (-not $userName) {
        Write-Host '  No interactive (console) user session found; skipping.'
        return
    }
    $system = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
    $admins = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
    $userId = New-Object System.Security.Principal.NTAccount($userName)
    try {
        $userId = $userId.Translate([System.Security.Principal.SecurityIdentifier])
    } catch { Write-Verbose "Could not resolve the SID of $userName; using the name." }

    $ctxDir = Join-Path $work ('_userctx-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
    $ctxFile = Join-Path $ctxDir 'dsregcmd-user.txt'
    $taskName = 'SherlogDsregcmd-' + [guid]::NewGuid().ToString('N').Substring(0, 12)
    $registered = $false
    try {
        New-Item -ItemType Directory -Path $ctxDir | Out-Null
        [IO.File]::WriteAllText($ctxFile, '')
        $fileSecurity = New-Object System.Security.AccessControl.FileSecurity
        $fileSecurity.SetAccessRuleProtection($true, $false)
        $fileSecurity.SetOwner($admins)
        foreach ($sid in @($system, $admins)) {
            $fileSecurity.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', 'Allow')))
        }
        $fileSecurity.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($userId, 'Modify', 'Allow')))
        Set-Acl -LiteralPath $ctxFile -AclObject $fileSecurity

        # cmd /c strips the outer quote pair: "<exe>" /status > "<file>" 2>&1
        $cmdArgs = '/d /c ""' + (Join-Path $sys32 'dsregcmd.exe') + '" /status > "' + $ctxFile + '" 2>&1"'
        $action = New-ScheduledTaskAction -Execute (Join-Path $sys32 'cmd.exe') -Argument $cmdArgs
        $principal = New-ScheduledTaskPrincipal -UserId $userName -LogonType Interactive -RunLevel Limited
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
                        -ExecutionTimeLimit (New-TimeSpan -Minutes 2)
        Register-ScheduledTask -TaskName $taskName -TaskPath '\' -Action $action -Principal $principal `
            -Settings $settings -Force | Out-Null
        $registered = $true
        Start-ScheduledTask -TaskName $taskName -TaskPath '\'

        # 267009 = 0x41301 running, 267011 = 0x41303 not yet run,
        # 267045 = 0x41325 queued; anything else is the finished exit code.
        $deadline = (Get-Date).AddSeconds(30)
        $done = $false
        $lastResult = $null
        do {
            Start-Sleep -Milliseconds 500
            $info = Get-ScheduledTaskInfo -TaskName $taskName -TaskPath '\' -ErrorAction SilentlyContinue
            $state = "$((Get-ScheduledTask -TaskName $taskName -TaskPath '\' -ErrorAction SilentlyContinue).State)"
            if ($info) {
                $lastResult = [int64]$info.LastTaskResult
                $done = ($lastResult -notin @(267009, 267011, 267045)) -and ($state -notin @('Running', 'Queued'))
            }
        } while (-not $done -and (Get-Date) -lt $deadline)
        if (-not $done) {
            throw "user-context task did not finish within 30 s (last result $lastResult; session locked, disconnected or task queued)"
        }
        if ((Get-Item -LiteralPath $ctxFile).Length -eq 0) {
            throw "user-context dsregcmd produced no output (task result $lastResult)"
        }
        Copy-Item -LiteralPath $ctxFile -Destination (Join-Path $work 'Identity\dsregcmd-status-user.txt') -Force
    } finally {
        if ($registered) {
            Unregister-ScheduledTask -TaskName $taskName -TaskPath '\' -Confirm:$false -ErrorAction SilentlyContinue
        }
        try { Remove-SherlogTree -Path $ctxDir } catch { Write-Warning "  Could not remove $ctxDir" }
    }
}

Invoke-Safe 'Certificates (machine + user)...' {
    $certutil = Join-Path $sys32 'certutil.exe'
    Invoke-SherlogNative $certutil @('-store', 'MY') | Out-File (Join-Path $work 'Identity\certs-machine-MY.txt')
    Invoke-SherlogNative $certutil @('-store', '-user', 'MY') | Out-File (Join-Path $work 'Identity\certs-user-MY.txt')

    # Highlight the machine certificates, including the Intune MDM device cert
    Get-ChildItem Cert:\LocalMachine\My |
        Select-Object Subject, Issuer, NotBefore, NotAfter, Thumbprint, @{n='Expired';e={$_.NotAfter -lt (Get-Date)}} |
        Format-List | Out-File (Join-Path $work 'Identity\certs-machine-overview.txt')
}

# ============================================================
# 5. Network
# ============================================================
Invoke-Safe 'Network configuration...' {
    $netsh = Join-Path $sys32 'netsh.exe'
    Invoke-SherlogNative (Join-Path $sys32 'ipconfig.exe') @('/all') | Out-File (Join-Path $work 'Network\ipconfig.txt')
    Invoke-SherlogNative $netsh @('advfirewall', 'show', 'allprofiles') | Out-File (Join-Path $work 'Network\firewall-profiles.txt')
    Invoke-SherlogNative $netsh @('advfirewall', 'show', 'global')      | Out-File (Join-Path $work 'Network\firewall-global.txt')
    Invoke-SherlogNative $netsh @('winhttp', 'show', 'proxy')           | Out-File (Join-Path $work 'Network\winhttp-proxy.txt')
    Invoke-SherlogNative $netsh @('wlan', 'show', 'profiles')           | Out-File (Join-Path $work 'Network\wlan-profiles.txt')
    Invoke-SherlogNative (Join-Path $sys32 'route.exe') @('print')      | Out-File (Join-Path $work 'Network\routes.txt')
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
    # On a proxy-only network a direct TCP test fails for every endpoint even
    # though the IME (which uses the WinHTTP proxy) is fine; test through the
    # proxy then, and record which path was tested.
    $netProxy = Get-SherlogProxy -TargetUrl 'https://login.microsoftonline.com/' -Explicit $Proxy
    if ($netProxy) {
        $results = @(Test-SherlogEndpoint -Endpoints $endpoints -ProxyUrl $netProxy -TimeoutMs 8000)
        $pathNote = "Tested with HTTPS requests through the WinHTTP proxy $netProxy."
    } else {
        $results = @(Test-SherlogEndpoint -Endpoints $endpoints -TimeoutMs 3000)
        $pathNote = 'Tested with direct TCP connects to port 443 (no WinHTTP proxy configured).'
    }
    $results | Format-Table Endpoint, Reachable, RemoteIP, Method -AutoSize |
        Out-File (Join-Path $work 'Network\endpoint-connectivity.txt')
    $pathNote | Out-File (Join-Path $work 'Network\endpoint-connectivity.txt') -Append
    # Locale-invariant twin (same pattern as firewall-profiles.json).
    $results | ConvertTo-Json | Out-File (Join-Path $work 'Network\endpoint-connectivity.json')

    # TLS-inspection detection: a plain port-443 handshake only proves *a* TLS
    # server answered. A real request's certificate issuer should be a
    # Microsoft/DigiCert CA; a locally-installed inspection proxy substitutes
    # its own issuer, which explains a lot of otherwise-mysterious app/sync
    # failures on managed networks. Goes through the same proxy as the IME.
    $tlsFile = Join-Path $work 'Network\tls-issuer-check.txt'
    $req = [Net.HttpWebRequest]::Create('https://login.microsoftonline.com/')
    $req.Timeout = 8000
    if ($netProxy) {
        $webProxy = New-Object System.Net.WebProxy($netProxy)
        $webProxy.UseDefaultCredentials = $true
        $req.Proxy = $webProxy
    }
    # An HTTP error status still completed the TLS handshake, so read the
    # certificate whatever GetResponse did.
    $probeError = $null
    try {
        $req.GetResponse().Close()
    } catch {
        $probeError = $_.Exception.Message
        $inner = $_.Exception.InnerException
        if ($inner -is [Net.WebException] -and $inner.Response) { $inner.Response.Close() }
    }
    $cert = $null
    try { $cert = $req.ServicePoint.Certificate } catch { $cert = $null }
    if ($cert) {
        "TLS certificate issuer for login.microsoftonline.com: $($cert.Issuer)" | Out-File $tlsFile
    } else {
        "TLS probe failed: $probeError" | Out-File $tlsFile
    }
    if ($netProxy) { "Probe sent through the WinHTTP proxy $netProxy." | Out-File $tlsFile -Append }
}

# ============================================================
# 6. Apps / Intune Management Extension
# ============================================================
Invoke-Safe 'Copying IME logs...' {
    $imeLogs = "$env:ProgramData\Microsoft\IntuneManagementExtension\Logs"
    if (-not (Test-Path -LiteralPath $imeLogs)) { return }
    $src = (Get-Item -LiteralPath $imeLogs).FullName.TrimEnd('\')
    $dest = Join-Path $work 'Apps-IME\Logs'
    New-Item -ItemType Directory -Path $dest -Force | Out-Null
    $files = @(Get-ChildItem -LiteralPath $src -File -Recurse -Force -ErrorAction SilentlyContinue)
    $budget = [long]::MaxValue
    if ($Remote) {
        # Slim profile: recent logs only (rotated archives go back months)
        # and a running size cap so the package stays uploadable.
        $cutoff = (Get-Date).AddDays(-14)
        $files = @($files | Where-Object { $_.LastWriteTime -gt $cutoff } | Sort-Object LastWriteTime -Descending)
        $budget = 40MB
    }
    # Per file, each with its own try/catch: one locked log must not abort
    # the rest, and relative paths are kept so same-named files in different
    # subfolders don't overwrite each other.
    $copied = 0
    $skipped = New-Object System.Collections.Generic.List[string]
    foreach ($file in $files) {
        if ($file.Length -gt $budget) { continue }
        $rel = $file.FullName.Substring($src.Length).TrimStart('\', '/')
        try {
            Copy-SherlogFile -Source $file.FullName -Destination (Join-Path $dest $rel)
            $budget -= $file.Length
            $copied++
        } catch {
            $skipped.Add("${rel}: $($_.Exception.Message)")
        }
    }
    if ($skipped.Count -gt 0) {
        $skipped | Out-File (Join-Path $work 'Apps-IME\logs-not-copied.txt')
        Write-Warning "  $($skipped.Count) IME log file(s) could not be copied (see Apps-IME\logs-not-copied.txt)."
    }
    if ($copied -eq 0 -and $files.Count -gt 0) {
        throw "none of the $($files.Count) IME log file(s) could be copied"
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
        Format-Table -AutoSize | Out-File (Join-Path $work 'Apps-IME\installed-apps.txt')
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
    Invoke-SherlogNative (Join-Path $sys32 'pnputil.exe') @('/enum-drivers') | Out-File (Join-Path $work 'System\drivers.txt')
    # Fails (non-zero, stderr) on devices without a battery - not an error.
    Invoke-SherlogNative (Join-Path $sys32 'powercfg.exe') @('/batteryreport', '/output', (Join-Path $work 'System\battery-report.html')) | Out-Null
    Get-ComputerInfo | Out-File (Join-Path $work 'System\computerinfo.txt')
    Get-HotFix | Sort-Object InstalledOn -Descending |
        Format-Table -AutoSize | Out-File (Join-Path $work 'System\hotfixes.txt')
}

Invoke-Safe 'Relevant scheduled tasks...' {
    $emTasks = Get-ScheduledTask -TaskPath '\Microsoft\Windows\EnterpriseMgmt\*' -ErrorAction SilentlyContinue
    $emTasks | Select-Object TaskPath, TaskName, State |
        Format-Table -AutoSize | Out-File (Join-Path $work 'System\enterprisemgmt-tasks.txt')
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
    Invoke-SherlogNative (Join-Path $sys32 'w32tm.exe') @('/query', '/status') | Out-File (Join-Path $work 'System\time-sync-status.txt')
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
            Invoke-SherlogNative $mpcmd @('-GetFiles') | Out-Null
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
    $dsreg = $script:dsregLines
    if (-not $dsreg) { $dsreg = @(Invoke-SherlogNative (Join-Path $sys32 'dsregcmd.exe') @('/status')) }
    $aadJoined = Get-DsregField -Lines $dsreg -Name 'AzureAdJoined'
    $prt       = Get-DsregField -Lines $dsreg -Name 'AzureAdPrt'
    $mdmUrl    = Get-DsregField -Lines $dsreg -Name 'MdmUrl'

    $imeService = (Get-Service -Name 'IntuneManagementExtension' -ErrorAction SilentlyContinue).Status

    $recentErrors = Get-WinEvent -LogName 'Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin' -MaxEvents 500 -ErrorAction SilentlyContinue |
        Where-Object Level -eq 2 |
        Select-Object -First 10 TimeCreated, Id, Message

    $anonLine = if ($Anonymize) {
        "`n [Anonymized] Best-effort redaction of tenant/company/user/device data in" +
        " text files. Binaries (evtx/cab/mdmdiag-zip/etl) are NOT scrubbed -" +
        " review before sharing.`n"
    } else { '' }
    $summaryDevice = if ($Anonymize) { $deviceLabel } else { $env:COMPUTERNAME }

    # ISO 8601 with offset: a bare local time is ambiguous once the package
    # leaves the device.
    $summary = @"
==========================================================
 INTUNE DIAGNOSTICS SUMMARY
 Device   : $summaryDevice
 Date     : $((Get-Date).ToString('o'))
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
$($recentErrors | Format-List | Out-String -Width 4096)

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
  _MANIFEST.json - collector version, profile, per-step and redaction outcome
==========================================================
"@
    $summary | Out-File (Join-Path $work '_SUMMARY.txt')
    Write-Host $summary
}

# ============================================================
# 11b. Secret redaction (always) + best-effort anonymization (-Anonymize)
# Stop the transcript first so CollectionTranscript.log can be scrubbed too.
# ============================================================
try { Stop-Transcript | Out-Null } catch { Write-Verbose 'No transcript to stop.' }

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

$anonOk = -not $Anonymize
$anonGaps = New-Object System.Collections.Generic.List[string]
if ($Anonymize) {
    Invoke-Safe 'Collecting anonymization tokens...' {
        # Every source on its own: one failing source (no WLAN service, no
        # BIOS serial) must not drop the others. Gaps land in the manifest.
        function Add-FromSource([string]$SourceName, [scriptblock]$Body) {
            try { & $Body } catch { $anonGaps.Add("${SourceName}: $($_.Exception.Message)") }
        }
        Add-FromSource 'dsregcmd' {
            $lines = $script:dsregLines
            if (-not $lines) { $lines = @(Invoke-SherlogNative (Join-Path $sys32 'dsregcmd.exe') @('/status')) }
            $userFile = Join-Path $work 'Identity\dsregcmd-status-user.txt'
            $userLines = @()
            if (Test-Path -LiteralPath $userFile) { $userLines = @(Get-Content -LiteralPath $userFile) }
            foreach ($set in @(, $lines) + @(, $userLines)) {
                Add-SherlogRedactToken -Map $redactMap -Value (Get-DsregField -Lines $set -Name 'TenantId')          -Tag '<TENANT-ID>'
                Add-SherlogRedactToken -Map $redactMap -Value (Get-DsregField -Lines $set -Name 'TenantName')        -Tag '<TENANT>'
                Add-SherlogRedactToken -Map $redactMap -Value (Get-DsregField -Lines $set -Name 'TenantDisplayName') -Tag '<COMPANY>'
                Add-SherlogRedactToken -Map $redactMap -Value (Get-DsregField -Lines $set -Name 'DeviceId')          -Tag '<DEVICE-ID>'
                Add-SherlogRedactToken -Map $redactMap -Value (Get-DsregField -Lines $set -Name 'IdpDomain')         -Tag '<DOMAIN>'
                # "AzureAD\JohnDoe, john@contoso.com" / "CORP\PC01$" /
                # "NT AUTHORITY\SYSTEM": split, so a machine account keeps
                # its trailing '$' for the server's SYSTEM detection.
                foreach ($acct in ((Get-DsregField -Lines $set -Name 'Executing Account Name') -split ',')) {
                    Add-SherlogAccountToken -Map $redactMap -Account $acct
                }
            }
        }
        Add-FromSource 'CloudDomainJoin' {
            Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo' `
                -ErrorAction SilentlyContinue | ForEach-Object {
                    $p = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
                    Add-SherlogRedactToken -Map $redactMap -Value $p.TenantId -Tag '<TENANT-ID>'
                    Add-SherlogAccountToken -Map $redactMap -Account $p.UserEmail
                }
            Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\TenantInfo' `
                -ErrorAction SilentlyContinue | ForEach-Object {
                    $p = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
                    Add-SherlogRedactToken -Map $redactMap -Value $p.DisplayName -Tag '<COMPANY>'
                    Add-SherlogRedactToken -Map $redactMap -Value $p.TenantName  -Tag '<TENANT>'
                }
        }
        Add-FromSource 'registered owner' {
            $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue
            Add-SherlogRedactToken -Map $redactMap -Value $cv.RegisteredOrganization -Tag '<COMPANY>'
            Add-SherlogRedactToken -Map $redactMap -Value $cv.RegisteredOwner        -Tag '<USER>'
        }
        Add-FromSource 'environment' {
            Add-SherlogRedactToken -Map $redactMap -Value $env:COMPUTERNAME -Tag '<DEVICE>'
            Add-SherlogRedactToken -Map $redactMap -Value $env:USERDNSDOMAIN -Tag '<DOMAIN>'
            # Under SYSTEM, USERNAME is the machine account (PC01$).
            Add-SherlogAccountToken -Map $redactMap -Account "$env:USERDOMAIN\$env:USERNAME"
        }
        Add-FromSource 'interactive user' {
            $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
            Add-SherlogAccountToken -Map $redactMap -Account $cs.UserName
            Add-SherlogRedactToken -Map $redactMap -Value $cs.Domain      -Tag '<DOMAIN>'
            Add-SherlogRedactToken -Map $redactMap -Value $cs.DNSHostName -Tag '<DEVICE>'
        }
        Add-FromSource 'user profiles' {
            $usersDir = Join-Path $env:SystemDrive 'Users'
            Get-ChildItem -LiteralPath $usersDir -Directory -Force -ErrorAction SilentlyContinue |
                Where-Object { -not ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -and
                               $_.Name -notmatch '^(Public|Default|Default User|All Users|defaultuser\d+)$' } |
                ForEach-Object { Add-SherlogRedactToken -Map $redactMap -Value $_.Name -Tag '<USER>' }
            Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' -ErrorAction SilentlyContinue |
                Where-Object { $_.PSChildName -match '^S-1-(5-21|12-1)-' } | ForEach-Object {
                    $img = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).ProfileImagePath
                    if ($img) { Add-SherlogRedactToken -Map $redactMap -Value (Split-Path $img -Leaf) -Tag '<USER>' }
                }
        }
        Add-FromSource 'serial number' {
            $bios = Get-CimInstance -ClassName Win32_BIOS -ErrorAction Stop
            Add-SherlogRedactToken -Map $redactMap -Value $bios.SerialNumber -Tag '<SERIAL>'
        }
        Add-FromSource 'Defender org id' {
            $atp = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status' -ErrorAction SilentlyContinue
            Add-SherlogRedactToken -Map $redactMap -Value $atp.OrgId -Tag '<ORG-ID>'
        }
        Add-FromSource 'Intune enrollments' {
            Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Enrollments' -ErrorAction SilentlyContinue | ForEach-Object {
                $e = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
                Add-SherlogAccountToken -Map $redactMap -Account $e.UPN
                $dm = Get-ItemProperty (Join-Path $_.PSPath 'DMClient\MS DM Server') -ErrorAction SilentlyContinue
                if ($dm) { Add-SherlogRedactToken -Map $redactMap -Value $dm.EntDMID -Tag '<INTUNE-DEVICE-ID>' }
            }
        }
        Add-FromSource 'Wi-Fi profiles' {
            $wlanDir = Join-Path $env:ProgramData 'Microsoft\Wlansvc\Profiles\Interfaces'
            Get-ChildItem -LiteralPath $wlanDir -Recurse -Filter '*.xml' -File -ErrorAction SilentlyContinue |
                ForEach-Object {
                    $xml = New-Object System.Xml.XmlDocument
                    $xml.Load($_.FullName)
                    foreach ($node in $xml.SelectNodes("//*[local-name()='name']")) {
                        Add-SherlogRedactToken -Map $redactMap -Value $node.InnerText -Tag '<SSID>'
                    }
                }
            # Fallback/complement: "    <label>   : <profile name>" lines.
            foreach ($line in @(Invoke-SherlogNative (Join-Path $sys32 'netsh.exe') @('wlan', 'show', 'profiles'))) {
                if ($line -match '^\s+\S[^:]*?\s*:\s+(\S.*?)\s*$') {
                    Add-SherlogRedactToken -Map $redactMap -Value $matches[1] -Tag '<SSID>'
                }
            }
        }
        $script:anonOk = $true
        Write-Host "  Collected $($redactMap.Count) value(s) to redact ($($anonGaps.Count) source gap(s))."
    }
}

$redaction = [pscustomobject]@{
    Performed = $false; Ok = $false; FilesScanned = 0; FilesChanged = 0
    FilesRemoved = 0; RemovedFiles = @(); BinaryFilesNotScrubbed = 0; Values = 0
}
$redactCtx = $null
if ($redactMap.Count -gt 0 -or $Anonymize) {
    $redaction.Performed = $true
    Invoke-Safe 'Redacting text files...' {
        $script:redactCtx = New-SherlogRedactionContext -Map $redactMap -Anonymize:$Anonymize
        $res = Invoke-TextRedaction -Root $work -Context $script:redactCtx
        $redaction.FilesScanned = $res.Scanned
        $redaction.FilesChanged = $res.Changed
        $redaction.FilesRemoved = $res.Removed.Count
        $redaction.RemovedFiles = @($res.Removed)
        $redaction.BinaryFilesNotScrubbed = $res.Binary
        $redaction.Values = $script:redactCtx.Values
        $redaction.Ok = $true
        Write-Host "  Redacted $($res.Changed) of $($res.Scanned) text file(s); removed $($res.Removed.Count) that could not be redacted."
    }
} else {
    $redaction.Ok = $true
}

if ($Anonymize) {
    Write-Warning ('ANONYMIZE is best-effort and NOT a guarantee. Only files that decode ' +
        'as text were redacted; binary files (event logs .evtx, Defender .cab, the nested ' +
        'mdmdiag .zip, .etl) are NOT scrubbed and may still contain tenant/company ' +
        'identifiers. Review the package before sharing.')
}

# ============================================================
# 11c. Collection manifest - written AFTER redaction so it reports the real
# outcome; its own text goes through the same redaction rules.
# ============================================================
Invoke-Safe 'Writing manifest...' {
    $manifest = [pscustomobject]@{
        CollectorVersion = $ScriptVersion
        WrapperVersion   = if ($WrapperVersion) { $WrapperVersion } else { $null }
        Profile          = if ($Remote) { 'Remote' } else { 'Full' }
        RunAsSystem      = ($env:USERNAME -eq 'SYSTEM' -or $env:USERDOMAIN -eq 'NT AUTHORITY' -or
                            [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -eq 'S-1-5-18')
        RunAsUser        = "$env:USERDOMAIN\$env:USERNAME"
        Anonymized       = ([bool]$Anonymize -and $redaction.Ok -and $anonOk -and $anonGaps.Count -eq 0)
        Redaction        = [pscustomobject]@{
            Performed              = $redaction.Performed
            Ok                     = $redaction.Ok
            FilesScanned           = $redaction.FilesScanned
            FilesChanged           = $redaction.FilesChanged
            FilesRemoved           = $redaction.FilesRemoved
            RemovedFiles           = $redaction.RemovedFiles
            BinaryFilesNotScrubbed = $redaction.BinaryFilesNotScrubbed
            AnonymizeGaps          = @($anonGaps)
        }
        StartedUtc       = $startedUtc.ToString('o')
        FinishedUtc      = ([DateTime]::UtcNow).ToString('o')
        OSBuild          = [Environment]::OSVersion.VersionString
        PSVersion        = $PSVersionTable.PSVersion.ToString()
        Steps            = $StepLog
    }
    $json = $manifest | ConvertTo-Json -Depth 5
    if ($script:redactCtx) {
        $json = Invoke-SherlogStringRedaction -Text $json -Context $script:redactCtx
    } elseif ($UploadToken) {
        $json = $json -replace [regex]::Escape($UploadToken), '<UPLOAD-TOKEN>'
    }
    $json | Out-File (Join-Path $work '_MANIFEST.json')
}

# ============================================================
# 12. Package everything
# ============================================================
Write-Step 'Packaging everything...'
try {
    if (Test-Path -LiteralPath $zipFile) { Remove-SherlogTree -Path $zipFile }
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [IO.Compression.ZipFile]::CreateFromDirectory($work, $zipFile, [IO.Compression.CompressionLevel]::Optimal, $false)
} finally {
    try { Remove-SherlogTree -Path $work } catch { Write-Warning "Could not remove the work folder $work" }
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
    Get-ChildItem -LiteralPath $OutputPath -Filter 'IntuneDiag-*.zip' -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -ne $zipFile -and $_.LastWriteTime -lt (Get-Date).AddDays(-7) } |
        ForEach-Object { Remove-SherlogTree -Path $_.FullName }
}

if ($UploadUrl) {
    $uploadProblem = Get-SherlogUploadProblem -Url $UploadUrl -Token $UploadToken
    $sizeMB = [math]::Round((Get-Item -LiteralPath $zipFile).Length / 1MB, 1)
    if ($uploadProblem) {
        Write-SherlogFailure "$uploadProblem; not uploaded (local zip kept)"
    } elseif (-not $redaction.Ok) {
        # Fail closed: an unredacted package would carry the token (and, with
        # -Anonymize, identifying data) to the server.
        Write-SherlogFailure 'redaction failed - package NOT uploaded (see _MANIFEST.json in the local zip)'
    } elseif (-not $anonOk) {
        Write-SherlogFailure 'collecting the anonymization values failed - package NOT uploaded'
    } elseif ($sizeMB -gt $MaxUploadMB) {
        Write-SherlogFailure "package too large ($sizeMB MB > $MaxUploadMB MB), not uploaded (local zip kept)"
    } else {
        $leak = $null
        $scanError = $null
        try { $leak = Find-SherlogSecretInZip -ZipPath $zipFile -Secret $UploadToken } catch { $scanError = $_.Exception.Message }
        if ($scanError) {
            Write-SherlogFailure "could not verify that the package is free of the upload token ($scanError) - not uploaded"
        } elseif ($leak) {
            try { Remove-SherlogTree -Path $zipFile } catch { Write-Warning "Could not delete $zipFile" }
            Write-SherlogFailure "upload token found in package entry '$leak' - not uploaded, package deleted"
        } else {
            Write-Step "Uploading to $UploadUrl ($sizeMB MB)..."
            # Re-detected rather than cached: a VPN or proxy change during a
            # long collection must not leave the upload with a stale proxy.
            $uploadProxy = Get-SherlogProxy -TargetUrl $UploadUrl -Explicit $Proxy
            # Size-aware timeout: 100 MB over a slow uplink needs far more
            # than the old fixed 180 s.
            $timeoutSec = [int][math]::Max(180, [math]::Ceiling($sizeMB * 8))
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
                        ContentType = 'application/zip'; Headers = $headers; TimeoutSec = $timeoutSec
                    }
                    if ($uploadProxy) {
                        $irmArgs['Proxy'] = $uploadProxy
                        $irmArgs['ProxyUseDefaultCredentials'] = $true
                    }
                    $resp = Invoke-RestMethod @irmArgs
                    # Only a real Sherlog answer counts: a captive portal or an
                    # inspecting proxy happily returns 200 with an HTML page.
                    $jobId = ''
                    if ($null -ne $resp -and $resp.PSObject.Properties['job_id']) { $jobId = "$($resp.job_id)" }
                    if ($jobId -cnotmatch '^[0-9a-f]{32}$') {
                        Write-SherlogFailure 'upload got an unexpected response without a Sherlog job id (captive portal or proxy page?); local zip kept'
                        break
                    }
                    $base = Get-SherlogBaseUrl -UploadUrl $UploadUrl
                    $link = "$($resp.url)"
                    if ($link -match '^https?://') { $resultUrl = $link }
                    elseif ($link.StartsWith('/')) { $resultUrl = "$base$link" }
                    else { $resultUrl = "$base/result/$jobId" }
                    # The full link is a bearer link to the package: console
                    # only (interactive admin runs), never the result line
                    # that ends up in Intune reports.
                    Write-Host "Uploaded. Review at: $resultUrl" -ForegroundColor Green
                    try { Remove-SherlogTree -Path $zipFile } catch { Write-Warning "Could not delete $zipFile" }
                    $uploaded = $true
                    # Single deterministic line for automation (e.g. the Intune
                    # remediation wrapper) - independent of -ForegroundColor
                    # and of Write-Host/Write-Warning, neither of which flows
                    # through a normal PowerShell pipe.
                    Write-Output "SHERLOG_RESULT=uploaded id=$($jobId.Substring(0, 8))"
                } catch {
                    $status = $null
                    try { $status = [int]$_.Exception.Response.StatusCode } catch { $status = $null }
                    $serverMsg = $_.ErrorDetails.Message
                    $reason = if ($serverMsg) { $serverMsg } else { $_.Exception.Message }
                    # 429 (inbox/server cap) does not clear within seconds;
                    # re-sending up to 100 MB twice more only adds load.
                    $permanent = $status -in 400, 401, 403, 404, 413, 429
                    if ($permanent -or $attempt -eq $maxAttempts) {
                        Write-SherlogFailure "upload failed ($status): $reason. Local zip kept: $zipFile"
                    } else {
                        Write-Host "  Attempt $attempt/$maxAttempts failed ($status): $reason - retrying..."
                        Start-Sleep -Seconds (5 * $attempt)
                    }
                }
            }
        }
    }
}
