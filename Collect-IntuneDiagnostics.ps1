<#
.SYNOPSIS
    Collects a complete diagnostics package from an Intune-managed Windows device.

.DESCRIPTION
    Mimics the Intune "Collect diagnostics" action and extends it with:
    - MDM logs via mdmdiagnosticstool.exe (all registered areas)
    - Relevant Event Logs (MDM, Entra/AAD, Device Registration, ESP/Shell-Core)
    - Registry exports (Enrollments, PolicyManager, IME, Autopilot)
    - Identity status (dsregcmd), certificates, network info
    - Intune Management Extension (IME) logs
    - Defender support files, Windows Update logs, system reports
    - Status of relevant services and scheduled tasks

    Result: a single zip file in C:\Temp (or a custom path).

.PARAMETER OutputPath
    Folder where the zip file will be created. Default: C:\Temp

.PARAMETER Remote
    Slim profile for unattended/Intune use: skips the slow and large sections
    (msinfo32, Get-WindowsUpdateLog, Defender -GetFiles cab) so the run stays
    well under the Intune script timeout and the Sherlog upload size limit,
    while keeping the IME logs, event logs, registry, identity and network data.

.PARAMETER UploadUrl
    When set, the resulting zip is uploaded to this Sherlog drop-off endpoint,
    e.g. https://sherlog.nl/api/diagnostics . Requires -UploadToken.

.PARAMETER UploadToken
    The self-chosen secret the admin generated on the Sherlog /inbox page. It
    authorizes the upload and is the key to view the uploads at /inbox.

.PARAMETER Anonymize
    Best-effort redaction of tenant and company data from the package: tenant id,
    tenant/company name, domain(s), UPN/e-mail, device name and user name are
    replaced with placeholders in all TEXT files, and the zip name + upload device
    name are anonymized. This is best-effort, NOT a guarantee: binary files
    (event logs .evtx, Defender .cab, .etl, the nested mdmdiag .zip) are NOT
    scrubbed and may still contain identifiers — review the package before
    sharing.

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
    [switch]$Anonymize
)

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

$folders = @('MDM','EventLogs','Registry','Identity','Network','Apps-IME','System','Defender','WindowsUpdate','Autopilot')
foreach ($f in $folders) {
    New-Item -ItemType Directory -Path (Join-Path $work $f) -Force | Out-Null
}

$transcript = Join-Path $work 'CollectionTranscript.log'
Start-Transcript -Path $transcript -Force | Out-Null

function Write-Step { param([string]$Msg) Write-Host "[$(Get-Date -Format 'HH:mm:ss')] $Msg" -ForegroundColor Cyan }
function Invoke-Safe {
    param([string]$Name, [scriptblock]$Action)
    Write-Step $Name
    try { & $Action } catch { Write-Warning "  Failed: $($_.Exception.Message)" }
}

# ============================================================
# 1. MDM logs (mdmdiagnosticstool, all areas)
# ============================================================
Invoke-Safe 'MDM diagnostics (all areas)...' {
    $areaKey = 'HKLM:\SOFTWARE\Microsoft\MdmDiagnostics\Area'
    if (Test-Path $areaKey) {
        $areas = (Get-ChildItem $areaKey).PSChildName -join ';'
        Write-Host "  Areas found: $areas"
        & "$env:windir\system32\mdmdiagnosticstool.exe" -area $areas -zip (Join-Path $work 'MDM\MDMDiag-AllAreas.zip') | Out-Null
    }
    # Always also generate the default report (HTML + XML + registry dump)
    & "$env:windir\system32\mdmdiagnosticstool.exe" -out (Join-Path $work 'MDM\DefaultReport') | Out-Null
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
    'Application'                 = 'Application'
    'System'                      = 'System'
}

foreach ($entry in $eventLogs.GetEnumerator()) {
    Invoke-Safe "Event log: $($entry.Key)..." {
        $dest = Join-Path $work "EventLogs\$($entry.Key).evtx"
        wevtutil epl $entry.Value $dest /ow:true 2>$null
        if (Test-Path $dest) {
            # Also create a readable text summary of errors/warnings (last 200 events)
            Get-WinEvent -LogName $entry.Value -MaxEvents 200 -ErrorAction SilentlyContinue |
                Where-Object { $_.Level -in 1,2,3 } |
                Select-Object TimeCreated, Id, LevelDisplayName, Message |
                Format-List | Out-File (Join-Path $work "EventLogs\$($entry.Key)-ErrorsWarnings.txt") -Width 250
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
    'MDM-Uninstall'            = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
    'InternetSettings'         = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings'
}

foreach ($entry in $regKeys.GetEnumerator()) {
    Invoke-Safe "Registry: $($entry.Key)..." {
        reg export $entry.Value (Join-Path $work "Registry\$($entry.Key).reg") /y 2>$null | Out-Null
    }
}

# ============================================================
# 4. Identity & certificates
# ============================================================
Invoke-Safe 'dsregcmd /status...' {
    dsregcmd /status | Out-File (Join-Path $work 'Identity\dsregcmd-status.txt')
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
}

Invoke-Safe 'Connectivity test to Intune/Entra endpoints...' {
    $endpoints = @(
        'login.microsoftonline.com',
        'enterpriseregistration.windows.net',
        'enrollment.manage.microsoft.com',
        'portal.manage.microsoft.com',
        'fef.msuc03.manage.microsoft.com',
        'graph.microsoft.com'
    )
    $results = foreach ($ep in $endpoints) {
        $t = Test-NetConnection -ComputerName $ep -Port 443 -WarningAction SilentlyContinue
        [pscustomobject]@{
            Endpoint  = $ep
            Reachable = $t.TcpTestSucceeded
            RemoteIP  = $t.RemoteAddress
        }
    }
    $results | Format-Table -AutoSize | Out-File (Join-Path $work 'Network\endpoint-connectivity.txt')
}

# ============================================================
# 6. Apps / Intune Management Extension
# ============================================================
Invoke-Safe 'Copying IME logs...' {
    $imeLogs = "$env:ProgramData\Microsoft\IntuneManagementExtension\Logs"
    if (Test-Path $imeLogs) {
        Copy-Item $imeLogs (Join-Path $work 'Apps-IME\Logs') -Recurse -Force
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
    Get-ScheduledTask -TaskPath '\Microsoft\Windows\EnterpriseMgmt\*' -ErrorAction SilentlyContinue |
        Select-Object TaskPath, TaskName, State |
        Format-Table -AutoSize | Out-File (Join-Path $work 'System\enterprisemgmt-tasks.txt') -Width 250
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
# Get-WindowsUpdateLog is slow (symbol decode); skip in the slim remote profile.
if (-not $Remote) {
    Invoke-Safe 'Windows Update log (this may take a while)...' {
        Get-WindowsUpdateLog -LogPath (Join-Path $work 'WindowsUpdate\WindowsUpdate.log') -ErrorAction SilentlyContinue | Out-Null
        Copy-Item "$env:ProgramData\USOShared\Logs\System\*.etl" (Join-Path $work 'WindowsUpdate') -Force -ErrorAction SilentlyContinue
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
    $aadJoined  = ($dsreg | Select-String 'AzureAdJoined\s*:\s*(\w+)').Matches.Groups[1].Value
    $prt        = ($dsreg | Select-String 'AzureAdPrt\s*:\s*(\w+)').Matches.Groups[1].Value
    $mdmUrl     = ($dsreg | Select-String 'MdmUrl\s*:\s*(.+)').Matches.Groups[1].Value

    $imeService = (Get-Service -Name 'IntuneManagementExtension' -ErrorAction SilentlyContinue).Status

    $recentErrors = Get-WinEvent -LogName 'Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin' -MaxEvents 500 -ErrorAction SilentlyContinue |
        Where-Object Level -eq 2 |
        Select-Object -First 10 TimeCreated, Id, Message

    $anonLine = if ($Anonymize) {
        "`n [Anonymized] Best-effort redaction of tenant/company/device data in" +
        " TEXT files. Binaries (evtx/cab/etl/mdmdiag-zip) are NOT scrubbed —" +
        " review before sharing.`n"
    } else { '' }

    $summary = @"
==========================================================
 INTUNE DIAGNOSTICS SUMMARY
 Device : $env:COMPUTERNAME
 Date   : $(Get-Date)
 User   : $env:USERNAME
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
  EventLogs\     - evtx exports + errors/warnings as text
  Registry\      - Enrollments, PolicyManager, IME, Autopilot
  Identity\      - dsregcmd, certificates
  Network\       - ipconfig, proxy, firewall, endpoint connectivity
  Apps-IME\      - IME logs, app inventory
  System\        - msinfo32, drivers, hotfixes, scheduled tasks
  Defender\      - MpSupportFiles.cab, status
  WindowsUpdate\ - WindowsUpdate.log, USO etl files
  Autopilot\     - setupact.log, provisioning logs
==========================================================
"@
    $summary | Out-File (Join-Path $work '_SUMMARY.txt')
    Write-Host $summary
}

# ============================================================
# 11b. Anonymize (best-effort) — text files only
# Stop the transcript first so CollectionTranscript.log is scrubbed too.
# ============================================================
Stop-Transcript | Out-Null
if ($Anonymize) {
    Invoke-Safe 'Anonymizing text files (best-effort)...' {
        $map = [System.Collections.Generic.List[object]]::new()
        function Add-Redact($val, $tag) {
            if ($null -eq $val) { return }
            $v = "$val".Trim()
            if ($v.Length -ge 3 -and @('WORKGROUP','Unknown','N/A','None') -notcontains $v) {
                $map.Add([pscustomobject]@{ Value = $v; Tag = $tag })
            }
        }
        $dsreg = dsregcmd /status
        function Get-Dsreg($name) {
            $line = $dsreg |
                Select-String ('^\s*' + [regex]::Escape($name) + '\s*:\s*(.+?)\s*$') |
                Select-Object -First 1
            if ($line) { $line.Matches[0].Groups[1].Value } else { '' }
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

        Add-Redact $env:COMPUTERNAME   '<DEVICE>'
        Add-Redact $env:USERNAME       '<USER>'
        Add-Redact $env:USERDNSDOMAIN  '<DOMAIN>'
        Add-Redact $env:USERDOMAIN     '<DOMAIN>'
        # Domain part of any UPN we found.
        foreach ($u in @($map | Where-Object { $_.Tag -eq '<UPN>' })) {
            if ($u.Value -match '@(.+)$') { Add-Redact $matches[1] '<DOMAIN>' }
        }

        # Longest values first so a domain inside a UPN doesn't get partially
        # replaced; de-dup case-insensitively.
        $seen = @{}
        $final = foreach ($r in ($map | Sort-Object { $_.Value.Length } -Descending)) {
            $k = $r.Value.ToLower()
            if (-not $seen.ContainsKey($k)) { $seen[$k] = $true; $r }
        }

        $emailRe = [regex]'(?i)[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}'
        $textExt = '.txt','.log','.reg','.xml','.html','.htm','.json','.csv','.ini','.config'
        $count = 0
        Get-ChildItem $work -Recurse -File |
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
                    foreach ($r in $final) {
                        $text = [regex]::Replace($text, [regex]::Escape($r.Value), $r.Tag, 'IgnoreCase')
                    }
                    $text = $emailRe.Replace($text, '<EMAIL>')
                    [IO.File]::WriteAllBytes($_.FullName, $enc.GetPreamble() + $enc.GetBytes($text))
                    $count++
                } catch { Write-Warning "  Could not anonymize $($_.Name): $($_.Exception.Message)" }
            }
        Write-Host "  Redacted $count text file(s) using $($final.Count) token(s)."
    }
    Write-Warning ('ANONYMIZE is best-effort and NOT a guarantee. Only TEXT files were ' +
        'redacted; binary files (event logs .evtx, Defender .cab, .etl, the nested ' +
        'mdmdiag .zip) are NOT scrubbed and may still contain tenant/company ' +
        'identifiers. Review the package before sharing.')
}

# ============================================================
# 12. Package everything
# ============================================================
Write-Step 'Packaging everything...'
Compress-Archive -Path "$work\*" -DestinationPath $zipFile -Force
Remove-Item $work -Recurse -Force

Write-Host ''
Write-Host "Done! Diagnostics package: $zipFile" -ForegroundColor Green

# ============================================================
# 13. Optional upload to Sherlog (drop-off API)
# ============================================================
if ($UploadUrl) {
    if (-not $UploadToken) {
        Write-Warning 'UploadUrl set without UploadToken; skipping upload. Local zip kept.'
    } else {
        Write-Step "Uploading to $UploadUrl ..."
        # TLS 1.2 for older Windows PowerShell 5.1 defaults.
        try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}
        try {
            $resp = Invoke-RestMethod -Uri $UploadUrl -Method Post -InFile $zipFile `
                -ContentType 'application/zip' -Headers @{
                    'X-Upload-Token' = $UploadToken
                    'X-Device-Name'  = $deviceLabel
                }
            $base = ($UploadUrl -replace '/api/diagnostics/?$', '')
            Write-Host "Uploaded. Review at: $base$($resp.url)" -ForegroundColor Green
            # Keep the device clean once it is safely uploaded.
            Remove-Item $zipFile -Force -ErrorAction SilentlyContinue
        } catch {
            Write-Warning "Upload failed: $($_.Exception.Message). Local zip kept: $zipFile"
        }
    }
}
