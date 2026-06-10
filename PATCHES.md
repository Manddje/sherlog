# PATCHES.md

Patches applied to the upstream `Get-IntuneManagementExtensionDiagnostics.ps1`
(Petri Paavola, v3.0) to make it run **headless on PowerShell Core / Linux**.

Goal: compatibility only. Analysis behavior and report format are unchanged.
Each patch is listed so it can be re-applied / merged after an upstream update.

Upstream source:
https://github.com/petripaavola/Get-IntuneManagementExtensionDiagnostics
(fetched main branch, version 3.0)

---

## Patch 1 — Cross-platform report path (backslash → `Join-Path`)

**Function / region:** HTML report creation block (`if($ExportHTML)` → "Create html").

**Why:**
The report path was built by string-concatenating the directory and filename
with a hardcoded Windows backslash:

```powershell
Out-File "$ReportSavePath\$HTMLFileName"
```

On Linux `\` is a **literal filename character**, not a path separator. With
`$ReportSavePath` being an absolute path like `/out`, the expression
`"$ReportSavePath\$HTMLFileName"` resolves to a leaf name containing a backslash
in the *parent* directory (e.g. the file `out\202...html` is created in `/`),
so the report does **not** land in the directory passed via
`-ExportHTMLReportPath`. The web layer (and `scripts/run-analysis.sh`) would
then fail to find the output. Verified: before the patch the file is misplaced
on the Ubuntu container; after the patch it is written to `/out/...html`.

**Original code:**

A single computed path used in 7 places, each as:
```powershell
"$ReportSavePath\$HTMLFileName"
```
(at the `Out-File`, `Get-ChildItem`, `Invoke-Item`, the success/opening
`Write-Host` lines, and the error `Write-Error`).

**New code:**

A cross-platform path is computed once, right after `$HTMLFileName` is set
(around line 5023):

```powershell
# PATCH (Linux compat): build report path with Join-Path instead of hardcoded
# backslash separator so the file is created in the intended directory on Linux,
# where '\' is a literal filename character. See PATCHES.md.
$ReportFullPath = Join-Path $ReportSavePath $HTMLFileName
```

and every `"$ReportSavePath\$HTMLFileName"` occurrence is replaced with
`"$ReportFullPath"` (lines 5816, 5826, 5845, 5857, 5859, 5862, 5872).

`Join-Path` emits the correct separator for the host OS, so the patch is a
no-op on Windows and correct on Linux.

---

## Notes — things deliberately NOT patched

- **`-ShowLogViewerUI` / `Out-GridView` code path:** untouched. It is Windows-only
  and we never invoke it; `-AllLogFiles -AllLogEntries` skip all selection UIs.

- **`Invoke-Item "$ReportFullPath"`** (open report in browser): left in place.
  On Linux it throws, but the call is wrapped in `try/catch` and is only reached
  when `-DoNotOpenReportAutomatically` is *not* given. `scripts/run-analysis.sh`
  always passes `-DoNotOpenReportAutomatically`, so the branch is skipped
  entirely in headless runs. No patch needed.

- **`$ComputerNameForReport = $env:ComputerName`** (lines ~357, ~1134): these live
  in the Autopilot-ESP block and the "use local `C:\ProgramData` logs" block —
  neither runs when `-LogFilesFolder` is supplied. In the `-LogFilesFolder` path
  the computer name is only filled from log content (a logged-on-user line); when
  absent it stays empty and the report simply shows a blank "Computer Name" and a
  `..._​_Intune_Logs_Report.html` filename. This is identical behavior on Windows
  and is cosmetic only, so it is intentionally left unchanged to keep patches
  minimal.

- **Hardcoded `C:\ProgramData\...` default log path** (lines ~377, ~1137): only used
  when `-LogFilesFolder`/`-LogFile` are omitted. We always pass `-LogFilesFolder`,
  so these are never hit. Not patched.
