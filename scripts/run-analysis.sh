#!/usr/bin/env bash
#
# run-analysis.sh — headless wrapper around Get-IntuneManagementExtensionDiagnostics.ps1
#
# Usage:
#   scripts/run-analysis.sh <input-dir> <output-dir>
#
#   <input-dir>   Directory containing IME .log files
#                 (IntuneManagementExtension.log, AgentExecutor.log, AppWorkload.log)
#   <output-dir>  Directory where the HTML report is written (created if missing)
#
# Exit code is that of the PowerShell script (propagated).

set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "Usage: $0 <input-dir> <output-dir>" >&2
    exit 2
fi

INPUT_DIR="$1"
OUTPUT_DIR="$2"

# Resolve script location so this works regardless of CWD.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PS_SCRIPT="$SCRIPT_DIR/Get-IntuneManagementExtensionDiagnostics.ps1"

if [[ ! -d "$INPUT_DIR" ]]; then
    echo "Input directory does not exist: $INPUT_DIR" >&2
    exit 2
fi
if [[ ! -f "$PS_SCRIPT" ]]; then
    echo "Analysis script not found: $PS_SCRIPT" >&2
    exit 2
fi

mkdir -p "$OUTPUT_DIR"

# Threshold (seconds) above which long-running PowerShell scripts are flagged
# in the timeline. pwsh binds this to [int] and fails hard on non-numeric
# input, so guard and fall back to the upstream default.
LONG_SCRIPT_THRESHOLD_SECONDS="${LONG_SCRIPT_THRESHOLD_SECONDS:-180}"
if ! [[ "$LONG_SCRIPT_THRESHOLD_SECONDS" =~ ^[0-9]+$ ]]; then
    echo "Invalid LONG_SCRIPT_THRESHOLD_SECONDS='$LONG_SCRIPT_THRESHOLD_SECONDS', using 180" >&2
    LONG_SCRIPT_THRESHOLD_SECONDS=180
fi

# -AllLogEntries -AllLogFiles  : suppress interactive selection UIs (headless)
# -ExportHTMLReportPath        : write report into the job output dir
# -DoNotOpenReportAutomatically: never try to launch a browser (Invoke-Item)
# -ShowErrorsInReport          : add ErrorLog rows with full PowerShell error text
# -ShowErrorsSummary           : print script-error summary to stdout (captured in job.json)
# -ShowAllTimelineEvents       : include Start rows for scripts/apps (visible progress)
# -ShowStdOutInReport          : no-op in upstream v3.0 (declared but unused); passed for
#                                forward compatibility — output would land in the report,
#                                which is already sandboxed and short-lived
pwsh -NoProfile -NonInteractive "$PS_SCRIPT" \
    -LogFilesFolder "$INPUT_DIR" \
    -AllLogEntries \
    -AllLogFiles \
    -ExportHTMLReportPath "$OUTPUT_DIR" \
    -DoNotOpenReportAutomatically \
    -ShowErrorsInReport \
    -ShowErrorsSummary \
    -ShowAllTimelineEvents \
    -ShowStdOutInReport \
    -LongRunningPowershellNotifyThreshold "$LONG_SCRIPT_THRESHOLD_SECONDS"

exit $?
