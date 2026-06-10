# testdata

IME log files used to verify the analyzer end-to-end.

> **Note:** these logs are **synthetic** (hand-crafted), not captured from a real
> device. The upstream project ships no sample logs, and no real anonymized logs
> were available when this phase was built. The lines are written in the exact
> CMTrace format the script's parser expects and exercise the real code paths:
>
> - `IntuneManagementExtension.log` — a successful Win32App install (Required
>   Install, exit 0), a failed Win32App (Required Uninstall, "Failed to create
>   installer process"), and a PowerShell script policy run.
> - `AgentExecutor.log` — a PowerShell command execution start/finish.
>
> Running the analyzer against these produces a non-empty timeline with
> Win32App and PowerShell-script events (see the project README / PATCHES.md).
>
> **Replace these with real (anonymized) IME logs** when available — the format
> and filenames must match (`*IntuneManagementExtension*.log`,
> `*AgentExecutor*.log`, `*AppWorkload*.log`).
