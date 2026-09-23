"""Tests for the two device scripts (Collect-IntuneDiagnostics.ps1 and
Remediate-CollectToSherlog.ps1).

Both run on Windows PowerShell 5.1 as SYSTEM, so most of their behaviour can't
be executed here. What can:
  * parsing (pwsh's parser is a superset of 5.1's, so a 5.1-syntax guard on
    the token stream is added on top),
  * the pure helper functions, which are pulled out of the script AST and run
    in pwsh (redaction, proxy parsing, secret scan, throttle/backoff, ...),
  * static contract checks that need no PowerShell at all.

Tests that need pwsh skip when it is not installed; the PSScriptAnalyzer test
skips when the module is absent.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import shutil
import struct
import subprocess
import zipfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
COLLECTOR = REPO_ROOT / "Collect-IntuneDiagnostics.ps1"
WRAPPER = REPO_ROOT / "Remediate-CollectToSherlog.ps1"
SCRIPTS = (COLLECTOR, WRAPPER)

PWSH = shutil.which("pwsh")
needs_pwsh = pytest.mark.skipif(PWSH is None, reason="pwsh not installed")

TOKEN = "shu_" + "Ab3dE6gH9jK2mN5pQ8sT1vW4yZ7_-xYz"   # [A-Za-z0-9_-], 36 chars

# Functions that must stay byte-identical in both scripts: the wrapper is
# pasted into Intune on its own and cannot dot-source the collector.
SHARED_FUNCTIONS = (
    "Enable-SherlogTls12", "Protect-SherlogText", "ConvertFrom-SherlogProxyServer",
    "ConvertFrom-SherlogWinHttpSetting", "Get-SherlogNetshProxy",
    "Test-SherlogProxyBypass", "Get-SherlogProxy", "Remove-SherlogTree",
    "New-SherlogDirSecurity", "Test-SherlogDirAcl", "Initialize-SherlogDir",
)

# Defines every top-level function of the script under test (from the AST,
# so none of the script body runs), then the test body follows.
_HARNESS = r"""
param([string]$ScriptPath)
$ErrorActionPreference = 'Stop'
$tokens = $null; $parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($ScriptPath, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw "parse errors in $ScriptPath" }
$fnPredicate = { param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }
foreach ($fn in $ast.FindAll($fnPredicate, $false)) {
    . ([scriptblock]::Create($fn.Extent.Text))
}
"""


def _function_text(script: Path, name: str) -> str:
    text = script.read_text(encoding="utf-8")
    m = re.search(rf"^function {re.escape(name)} \{{.*?^\}}\n", text, re.M | re.S)
    assert m, f"function {name} not found in {script.name}"
    return m.group(0)


def run_ps(tmp_path: Path, body: str, script: Path = COLLECTOR):
    """Run `body` in pwsh with the script's functions defined; the body's
    stdout must be one JSON document, which is returned parsed."""
    ps1 = tmp_path / "harness.ps1"
    ps1.write_text(_HARNESS + "\n" + body, encoding="utf-8")
    r = subprocess.run([PWSH, "-NoProfile", "-NonInteractive", "-File", str(ps1),
                        "-ScriptPath", str(script)],
                       capture_output=True, text=True, timeout=300)
    assert r.returncode == 0, f"pwsh failed:\nSTDOUT:\n{r.stdout}\nSTDERR:\n{r.stderr}"
    return json.loads(r.stdout)


def ps_str(value: str) -> str:
    """PowerShell single-quoted string literal."""
    return "'" + value.replace("'", "''") + "'"


# --- parsing and PS 5.1 syntax ------------------------------------------------

@needs_pwsh
@pytest.mark.parametrize("script", SCRIPTS, ids=lambda p: p.name)
def test_script_parses_without_errors(tmp_path, script):
    body = r"""
$t = $null; $e = $null
[void][System.Management.Automation.Language.Parser]::ParseFile($ScriptPath, [ref]$t, [ref]$e)
ConvertTo-Json -Compress -InputObject @($e | ForEach-Object { "line $($_.Extent.StartLineNumber): $($_.Message)" })
"""
    # The harness itself throws on parse errors; report them explicitly too.
    ps1 = tmp_path / "parse.ps1"
    ps1.write_text("param([string]$ScriptPath)\n" + body, encoding="utf-8")
    r = subprocess.run([PWSH, "-NoProfile", "-NonInteractive", "-File", str(ps1),
                        "-ScriptPath", str(script)], capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stderr
    assert json.loads(r.stdout) == []


# PS 7-only syntax the 5.1 parser rejects, as token kinds, plus PS 6/7-only
# parameters/commands that parse fine but fail at runtime on 5.1.
_PS7_TOKEN_KINDS = {"QuestionMark", "QuestionQuestion", "QuestionQuestionEquals",
                    "QuestionDot", "QuestionLBracket", "AndAnd", "OrOr", "Clean"}
_PS7_PARAMETERS = {"-ashashtable", "-parallel", "-skipcertificatecheck",
                   "-skiphttperrorcheck", "-noproxy", "-statuscodevariable",
                   "-responseheadersvariable", "-authentication", "-sslprotocol",
                   "-form", "-resume", "-maximumretrycount", "-retryintervalsec",
                   "-asarray", "-enumsasstrings", "-followrellink",
                   "-skipheadervalidation"}
_PS7_COMMANDS = {"join-string", "get-error", "test-json", "convertfrom-markdown",
                 "get-uptime", "remove-alias"}


@needs_pwsh
@pytest.mark.parametrize("script", SCRIPTS, ids=lambda p: p.name)
def test_no_ps7_only_syntax(tmp_path, script):
    """Windows PowerShell 5.1 is the runtime. Inspect the token stream (not
    raw text, so comments mentioning '??' or '&&' don't count)."""
    tokens = run_ps(tmp_path, r"""
$t = $null; $e = $null
[void][System.Management.Automation.Language.Parser]::ParseFile($ScriptPath, [ref]$t, [ref]$e)
@($t | ForEach-Object { [pscustomobject]@{ Kind = "$($_.Kind)"; Text = $_.Text; Line = $_.Extent.StartLineNumber } }) |
    ConvertTo-Json -Compress
""", script)
    bad = []
    for tok in tokens:
        kind, text = tok["Kind"], tok["Text"]
        if kind in _PS7_TOKEN_KINDS:
            bad.append(tok)
        elif kind == "Parameter" and text.lower().rstrip(":") in _PS7_PARAMETERS:
            bad.append(tok)
        elif kind in ("Generic", "Identifier") and text.lower() in _PS7_COMMANDS:
            bad.append(tok)
        elif kind == "StringLiteral" and text.strip("'\"").lower() in ("utf8nobom", "utf8bom"):
            bad.append(tok)
        elif kind == "Variable" and text.lower() in ("$psstyle",):
            bad.append(tok)
    assert not bad, f"PS 7-only constructs in {script.name}: {bad}"


def test_ps7_guard_catches_real_ps7_code(tmp_path):
    """Sanity check of the guard above on a deliberately bad snippet."""
    if PWSH is None:
        pytest.skip("pwsh not installed")
    bad = tmp_path / "bad.ps1"
    bad.write_text("# a ?? b in a comment is fine\n$x = $a ?? 'b'\n$y = $c ? 1 : 2\n"
                   "'{}' | ConvertFrom-Json -AsHashtable\n", encoding="utf-8")
    tokens = run_ps(tmp_path, r"""
$t = $null; $e = $null
[void][System.Management.Automation.Language.Parser]::ParseFile($ScriptPath, [ref]$t, [ref]$e)
@($t | ForEach-Object { [pscustomobject]@{ Kind = "$($_.Kind)"; Text = $_.Text } }) | ConvertTo-Json -Compress
""", bad)
    kinds = {t["Kind"] for t in tokens}
    assert {"QuestionQuestion", "QuestionMark"} <= kinds
    assert any(t["Text"].lower() == "-ashashtable" for t in tokens)


# --- static contract checks (no PowerShell needed) ----------------------------

def test_shared_helpers_are_identical_in_both_scripts():
    for name in SHARED_FUNCTIONS:
        assert _function_text(COLLECTOR, name) == _function_text(WRAPPER, name), name


def test_wrapper_integrity_pin_contract():
    """The server replaces the literal placeholder with the uppercase SHA-256
    of what /collect-script serves; it must occur exactly once (in the
    settings line), or a replaced copy elsewhere would defeat the
    'unreplaced placeholder' check."""
    text = WRAPPER.read_text(encoding="utf-8")
    assert text.count("<COLLECTOR-SHA256>") == 1
    assert text.count("$CollectorSha256 = '<COLLECTOR-SHA256>'") == 1
    code = "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))
    assert "Get-FileHash -LiteralPath $collector -Algorithm SHA256" in code
    assert "if ($actual -ne $CollectorSha256)" in code              # -ne: case-insensitive
    assert "$CollectorSha256 -notmatch '^[0-9A-Fa-f]{64}$'" in code
    # Rejected download is deleted before anything runs it.
    mismatch = code.split("if ($actual -ne $CollectorSha256)")[1].split("\n        }")[0]
    assert "Remove-SherlogTree -Path $collector" in mismatch
    # Download goes through the WinHTTP proxy like the upload does.
    assert "$download['ProxyUseDefaultCredentials'] = $true" in code
    # https only, localhost exempt for testing.
    assert "$SherlogBase -notmatch '^https://" in code


def test_wrapper_settings_are_first_matches_for_inbox_generator():
    """/inbox fills the script with JS .replace() on the FIRST match of these
    patterns, so no earlier text may look like an assignment."""
    text = WRAPPER.read_text(encoding="utf-8")
    for var, line in (("SherlogBase", "$SherlogBase = 'https://sherlog.nl'"),
                      ("UploadToken", "$UploadToken = '<PASTE-YOUR-TOKEN-HERE>'"),
                      ("CollectionMode", "$CollectionMode      = 'full'")):
        m = re.search(rf"\${var}\s*=\s*'[^']*'", text)
        assert m and text.index(line) == m.start(), var


def test_scripts_refuse_the_inbox_key():
    for script in SCRIPTS:
        code = script.read_text(encoding="utf-8")
        assert "-like 'shk_*'" in code, script.name
    collector = COLLECTOR.read_text(encoding="utf-8")
    # The collector refuses before collecting anything (and before the ping).
    assert (collector.index("if ($UploadToken -like 'shk_*') {")
            < collector.index("Send-SherlogPing -Phase start"))


def test_result_line_carries_no_bearer_link():
    collector = COLLECTOR.read_text(encoding="utf-8")
    wrapper = WRAPPER.read_text(encoding="utf-8")
    assert 'Write-Output "SHERLOG_RESULT=uploaded id=$($jobId.Substring(0, 8))"' in collector
    assert "SHERLOG_RESULT=$resultUrl" not in collector
    # Success only with a real 32-hex job id (captive portal 200 = failure).
    assert "$jobId -cnotmatch '^[0-9a-f]{32}$'" in collector
    # 429 is permanent: no 100 MB re-uploads 5/10 s later.
    assert "$permanent = $status -in 400, 401, 403, 404, 413, 429" in collector
    # The wrapper never persists the result link (Users-readable registry).
    code = "\n".join(l for l in wrapper.splitlines() if not l.lstrip().startswith("#"))
    assert "Set-ItemProperty -Path $stateKey -Name LastResultUrl" not in code
    assert "-Name LastResultId -Value $ResultId" in code
    assert "Remove-ItemProperty -Path $stateKey -Name LastResultUrl" in code


def test_wrapper_captures_all_streams_and_fails_without_result():
    code = WRAPPER.read_text(encoding="utf-8")
    assert "$records = @(& $collector @collectorArgs *>&1)" in code
    # Only a SHERLOG_RESULT line gives exit 0; everything else ends in exit 1.
    assert "$exitCode = 1" in code
    assert code.count("$exitCode = 0") == 1
    assert "Exit-Sherlog $exitCode $summary" in code
    # A registry key is never recreated with New-Item -Force (wipes values).
    assert not re.search(r"New-Item -Path \$stateKey[^\n]*-Force", code)


def test_no_recursive_remove_item_or_legacy_constructs():
    """Remove-Item -Recurse follows junctions on PS 5.1; C:\\Temp is
    user-writable; schtasks /RU prompts for a password; Test-NetConnection
    takes ~20 s per dead endpoint."""
    for script in SCRIPTS:
        code = "\n".join(l for l in script.read_text(encoding="utf-8").splitlines()
                         if not l.lstrip().startswith("#"))
        assert not re.search(r"Remove-Item[^\n]*-Recurse", code), script.name
        assert "icacls" not in code, script.name
        assert "BUILTIN\\Administrators" not in code, script.name
    collector = COLLECTOR.read_text(encoding="utf-8")
    assert "C:\\Temp" not in collector                      # help text included
    collector = "\n".join(l for l in collector.splitlines() if not l.lstrip().startswith("#"))
    assert "schtasks" not in collector.lower()
    assert "Test-NetConnection" not in collector
    assert "WriteAllBytes" not in collector
    assert "'/reg:64'" in collector
    assert "$PSDefaultParameterValues['Out-File:Width'] = 4096" in collector
    assert "Register-ScheduledTask" in collector and "Unregister-ScheduledTask" in collector
    assert "-LogonType Interactive -RunLevel Limited" in collector


def test_versions():
    collector = COLLECTOR.read_text(encoding="utf-8")
    wrapper = WRAPPER.read_text(encoding="utf-8")
    assert re.search(r"^\$ScriptVersion = '1\.4\.\d+'$", collector, re.M)
    assert re.search(r"^\$WrapperVersion = '1\.4\.\d+'$", wrapper, re.M)
    assert "WrapperVersion   = if ($WrapperVersion)" in collector   # in the manifest


# --- functional: redaction ------------------------------------------------------

@needs_pwsh
def test_name_like_values_are_redacted_as_whole_words_only(tmp_path):
    out = run_ps(tmp_path, r"""
$map = New-Object System.Collections.Generic.List[object]
$map.Add([pscustomobject]@{ Value = 'CORP'; Tag = '<DOMAIN>' })
$map.Add([pscustomobject]@{ Value = 'admin'; Tag = '<USER>' })
$map.Add([pscustomobject]@{ Value = 'PC-0042'; Tag = '<DEVICE>' })
$ctx = New-SherlogRedactionContext -Map $map
$text = "CORP\admin on PC-0042 at Contoso Corporation; admin is in Administrators; RunAsadmin=1; corp_admin; IntuneDiag-PC-0042-20240101"
# Well-known/generic values never enter the map at all.
$m2 = New-Object System.Collections.Generic.List[object]
foreach ($v in 'User', 'SYSTEM', 'NT AUTHORITY\SYSTEM', 'Owner', 'abc', 'WORKGROUP', 'defaultuser0', 'AzureAD') {
    Add-SherlogRedactToken -Map $m2 -Value $v -Tag '<USER>'
}
$m3 = New-Object System.Collections.Generic.List[object]
Add-SherlogAccountToken -Map $m3 -Account 'CORP\PC01$'
Add-SherlogAccountToken -Map $m3 -Account ' jan.jansen@contoso.com'
@{ out = (Invoke-SherlogStringRedaction -Text $text -Context $ctx); generic = $m2.Count
   acct = @($m3 | ForEach-Object { "$($_.Tag)=$($_.Value)" }) } | ConvertTo-Json -Compress
""")
    t = out["out"]
    assert t.startswith("<DOMAIN>\\<USER> on <DEVICE> at")
    assert "Contoso Corporation" in t
    assert "in Administrators" in t
    assert "RunAsadmin=1" in t                     # inside a word: untouched
    assert "<DOMAIN>_<USER>" in t                  # '_' is a boundary
    assert "IntuneDiag-<DEVICE>-20240101" in t
    assert out["generic"] == 0
    # Machine account keeps its '$' marker via the <DEVICE> tag.
    assert out["acct"] == ["<DOMAIN>=CORP", "<DEVICE>=PC01",
                           "<UPN>=jan.jansen@contoso.com", "<DOMAIN>=contoso.com"]


@needs_pwsh
def test_email_and_network_identifiers(tmp_path):
    out = run_ps(tmp_path, r"""
$ctx = New-SherlogRedactionContext -Anonymize
$text = @(
  'mail john.doe+x@contoso.com and @mention and user@localhost',
  'ip 10.1.2.3 and 192.168.0.10. loop 127.0.0.1 any 0.0.0.0 mask 255.255.255.0',
  'Version 1.0.0.0 "DisplayVersion"="10.2.3.4" ProductVersion: 4.3.2.1',
  'build 10.0.19045.3693 app 1.2.3.4.5',
  'mac 00-15-5D-01-02-03 and aa:bb:cc:dd:ee:ff',
  'v6 fe80::1c2d:3e4f:5a6b:7c8d%12 and 2001:db8:0:0:0:0:0:1 loop ::1',
  'time="09:47:21.1234567" 12:34:56 guid 3f2504e0-4f89-11d3-9a0c-0305e82c3301',
  'sid S-1-5-21-1004336348-1177238915-682003330-1001 entra S-1-12-1-111-222-333-444 system S-1-5-18'
) -join "`n"
@{ out = (Invoke-SherlogStringRedaction -Text $text -Context $ctx) } | ConvertTo-Json -Compress
""")
    lines = out["out"].split("\n")
    assert lines[0] == "mail <EMAIL> and @mention and user@localhost"
    assert lines[1] == ("ip <IPV4> and <IPV4>. loop 127.0.0.1 any 0.0.0.0 "
                        "mask 255.255.255.0")
    assert lines[2] == 'Version 1.0.0.0 "DisplayVersion"="10.2.3.4" ProductVersion: 4.3.2.1'
    assert lines[3] == "build 10.0.19045.3693 app 1.2.3.4.5"
    assert lines[4] == "mac <MAC> and <MAC>"
    assert lines[5] == "v6 <IPV6> and <IPV6> loop ::1"
    assert lines[6] == ('time="09:47:21.1234567" 12:34:56 guid '
                        "3f2504e0-4f89-11d3-9a0c-0305e82c3301")
    assert lines[7] == "sid <SID> entra <SID> system S-1-5-18"


@needs_pwsh
def test_json_escaped_and_reg_hex_forms(tmp_path):
    out = run_ps(tmp_path, r"""
$map = New-Object System.Collections.Generic.List[object]
$map.Add([pscustomobject]@{ Value = "O'Brien & Sons"; Tag = '<COMPANY>' })
$map.Add([pscustomobject]@{ Value = 'CORP'; Tag = '<DOMAIN>' })
$ctx = New-SherlogRedactionContext -Map $map
$json = @{ Org = "O'Brien & Sons" } | ConvertTo-Json -Compress
$ps51json = '{"Org":"O\u0027Brien \u0026 Sons"}'
# reg.exe wraps hex lists with ",\" + CRLF + two spaces - here inside 'R'.
$reg = "`"Path`"=hex(2):25,00,43,00,6f,00,52,00,\`r`n  70,00,25,00,00,00`r`n`"Other`"=hex(2):43,00,6f,00,72,00,70,00,6f,00,72,00,61,00,74,00,65,00,00,00"
@{
  json   = (Invoke-SherlogStringRedaction -Text $json -Context $ctx)
  ps51   = (Invoke-SherlogStringRedaction -Text $ps51json -Context $ctx)
  reg    = (Invoke-SherlogStringRedaction -Text $reg -Context $ctx -IsReg)
  notreg = (Invoke-SherlogStringRedaction -Text $reg -Context $ctx)
  taghex = (ConvertTo-SherlogRegHex -Value '<DOMAIN>')
} | ConvertTo-Json -Compress
""")
    assert "Brien" not in out["json"] and "<COMPANY>" in out["json"]
    assert out["ps51"] == '{"Org":"<COMPANY>"}'
    tag_hex = ",".join(f"{b:02x}" for b in "<DOMAIN>".encode("utf-16-le"))
    assert out["taghex"] == tag_hex
    # %CoRp% -> %<DOMAIN>%, across the line wrap and case-insensitive.
    assert out["reg"].startswith(f'"Path"=hex(2):25,00,{tag_hex},25,00,00,00')
    # Hex rules only apply to .reg files.
    assert out["notreg"].startswith('"Path"=hex(2):25,00,43,00,6f,00')
    # Whole-word rule in hex form too: CORP inside "Corporate" survives.
    assert out["reg"].endswith("43,00,6f,00,72,00,70,00,6f,00,72,00,61,00,74,00,65,00,00,00")


@needs_pwsh
def test_upload_token_redacted_in_utf8_utf16_latin1_and_base64(tmp_path):
    pkg = tmp_path / "pkg"
    (pkg / "Apps-IME" / "Logs").mkdir(parents=True)
    (pkg / "EventLogs").mkdir()
    # UTF-8 without BOM (transcript-like).
    (pkg / "CollectionTranscript.log").write_bytes(
        f"Command: Collect.ps1 -UploadToken {TOKEN} -Remote\n".encode())
    # UTF-16LE with BOM (PS 5.1 Out-File default / reg export).
    (pkg / "a.txt").write_bytes(b"\xff\xfe" + f"token={TOKEN}\r\n".encode("utf-16-le"))
    # UTF-16LE without BOM, and without a text extension (content sniffing).
    (pkg / "Apps-IME" / "Logs" / "noext").write_bytes(f"x {TOKEN} y".encode("utf-16-le"))
    # ANSI/Latin-1 text: must survive byte-for-byte apart from the token.
    latin = f"caf\xe9 {TOKEN} na\xefve".encode("latin-1")
    (pkg / "latin.log").write_bytes(latin)
    # Script body base64-embedded in an IME log (the wrapper carries the token).
    body = f"$UploadToken = '{TOKEN}'\r\n".encode("utf-8")
    b64 = base64.b64encode(b"\xef\xbb\xbf# script\r\n" + body).decode()
    (pkg / "Apps-IME" / "Logs" / "AgentExecutor.log").write_text(
        f'<![LOG[policy {{"ScriptBody":"{b64}"}}]LOG]!>', encoding="utf-8")
    # Known binary: skipped by redaction (the zip scan catches it instead).
    (pkg / "EventLogs" / "x.evtx").write_bytes(b"ElfFile\x00" + TOKEN.encode("utf-16-le"))

    out = run_ps(tmp_path, rf"""
$map = New-Object System.Collections.Generic.List[object]
$map.Add([pscustomobject]@{{ Value = {ps_str(TOKEN)}; Tag = '<UPLOAD-TOKEN>' }})
$ctx = New-SherlogRedactionContext -Map $map
$res = Invoke-TextRedaction -Root {ps_str(str(pkg))} -Context $ctx
@{{ scanned = $res.Scanned; changed = $res.Changed; binary = $res.Binary; removed = @($res.Removed) }} |
    ConvertTo-Json -Compress
""")
    assert out["removed"] == []
    assert out["binary"] == 1
    assert out["changed"] == 5
    utf16 = (pkg / "a.txt").read_bytes()
    assert utf16.startswith(b"\xff\xfe")                      # BOM preserved
    assert utf16[2:].decode("utf-16-le") == "token=<UPLOAD-TOKEN>\r\n"
    assert (pkg / "Apps-IME" / "Logs" / "noext").read_bytes() == \
        "x <UPLOAD-TOKEN> y".encode("utf-16-le")
    assert (pkg / "latin.log").read_bytes() == "caf\xe9 <UPLOAD-TOKEN> na\xefve".encode("latin-1")
    transcript = (pkg / "CollectionTranscript.log").read_bytes()
    assert not transcript.startswith(b"\xef\xbb\xbf")         # no BOM added
    assert TOKEN.encode() not in transcript
    log = (pkg / "Apps-IME" / "Logs" / "AgentExecutor.log").read_text(encoding="utf-8")
    decoded = base64.b64decode(re.search(r'"ScriptBody":"([^"]+)"', log).group(1))
    assert TOKEN.encode() not in decoded
    assert b"# script" in decoded                               # blob still decodes
    assert TOKEN.encode("utf-16-le") in (pkg / "EventLogs" / "x.evtx").read_bytes()


@needs_pwsh
def test_redaction_fails_closed_by_removing_the_file(tmp_path):
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "bad.txt").write_text("a" * 40 + "!", encoding="utf-8")
    (pkg / "good.txt").write_text("fine", encoding="utf-8")
    out = run_ps(tmp_path, rf"""
# A rule that always times out stands in for any per-file failure.
$slow = [regex]::new('(a+)+$', [Text.RegularExpressions.RegexOptions]::None, [TimeSpan]::FromTicks(1))
$ctx = [pscustomobject]@{{ Rules = @([pscustomobject]@{{ Re = $slow; Tag = 'x'; RegOnly = $false }}); Anonymize = $false }}
$res = Invoke-TextRedaction -Root {ps_str(str(pkg))} -Context $ctx 3>$null
@{{ removed = @($res.Removed) }} | ConvertTo-Json -Compress
""")
    assert "bad.txt" in out["removed"]
    assert not (pkg / "bad.txt").exists()


# --- functional: secret scan of the finished zip --------------------------------

@needs_pwsh
def test_zip_secret_scan(tmp_path):
    clean = tmp_path / "clean.zip"
    with zipfile.ZipFile(clean, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("a.txt", "nothing to see " * 1000)
        z.writestr("EventLogs/x.evtx", b"\x00" * 5000)
    utf16 = tmp_path / "utf16.zip"
    with zipfile.ZipFile(utf16, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("a.txt", "fine")
        # Straddles the 1 MiB read-chunk boundary.
        z.writestr("EventLogs/x.evtx", b"\x01" * (1048576 - 7) + TOKEN.encode("utf-16-le"))
    nested_inner = tmp_path / "inner.zip"
    with zipfile.ZipFile(nested_inner, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("deep/file.txt", f"x{TOKEN}x")
    nested = tmp_path / "nested.zip"
    with zipfile.ZipFile(nested, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("MDM/MDMDiag-AllAreas.zip", nested_inner.read_bytes())
    b64 = tmp_path / "b64.zip"
    with zipfile.ZipFile(b64, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("ime.log", base64.b64encode(b"ab" + TOKEN.encode()).decode())
    out = run_ps(tmp_path, rf"""
$r = [ordered]@{{}}
foreach ($n in 'clean', 'utf16', 'nested', 'b64') {{
    $r[$n] = Find-SherlogSecretInZip -ZipPath (Join-Path {ps_str(str(tmp_path))} "$n.zip") -Secret {ps_str(TOKEN)}
}}
$r | ConvertTo-Json -Compress
""")
    assert out == {"clean": None, "utf16": "EventLogs/x.evtx",
                   "nested": "MDM/MDMDiag-AllAreas.zip!/deep/file.txt", "b64": "ime.log"}


@needs_pwsh
def test_base64_cores_cover_every_alignment(tmp_path):
    cores = run_ps(tmp_path, rf"""
@(Get-SherlogBase64Core -Secret {ps_str(TOKEN)}) | ConvertTo-Json -Compress
""")
    assert len(cores) == 6
    for raw in (TOKEN.encode(), TOKEN.encode("utf-16-le")):
        for pad in (b"", b"x", b"xy"):
            encoded = base64.b64encode(pad + raw + b"tail").decode()
            assert any(c in encoded for c in cores), (raw[:4], pad)


# --- functional: proxy parsing -------------------------------------------------

@needs_pwsh
@pytest.mark.parametrize("script", SCRIPTS, ids=lambda p: p.name)
def test_proxy_parsing(tmp_path, script):
    def winhttp(flags: int, server: str, bypass: str) -> str:
        blob = struct.pack("<iii", 0x28, 7, flags)
        blob += struct.pack("<i", len(server)) + server.encode()
        blob += struct.pack("<i", len(bypass)) + bypass.encode()
        return ",".join(str(b) for b in blob)

    out = run_ps(tmp_path, rf"""
$r = [ordered]@{{}}
$r.perProto   = ConvertFrom-SherlogProxyServer -Server 'http=a.corp:80;https=b.corp:443'
$r.httpOnly   = ConvertFrom-SherlogProxyServer -Server 'http=a.corp:80;ftp=f:21'
$r.plain      = ConvertFrom-SherlogProxyServer -Server 'proxy.corp:8080'
$r.withScheme = ConvertFrom-SherlogProxyServer -Server 'http://proxy.corp:3128/'
$r.socksOnly  = ConvertFrom-SherlogProxyServer -Server 'socks=s.corp:1080'
$r.list       = ConvertFrom-SherlogProxyServer -Server ' p1:1 ; p2:2 '
$r.empty      = ConvertFrom-SherlogProxyServer -Server ''
$reg = ConvertFrom-SherlogWinHttpSetting -Bytes ([byte[]]@({winhttp(3, 'http=a:80;https=b:443', '<local>;*.corp.local')}))
$r.regServer = $reg.Server; $r.regBypass = $reg.Bypass
$r.regDirect = (ConvertFrom-SherlogWinHttpSetting -Bytes ([byte[]]@({winhttp(1, '', '')}))).Server
$r.regShort  = $null -eq (ConvertFrom-SherlogWinHttpSetting -Bytes ([byte[]]@(1, 2, 3)))
$en = @('', 'Current WinHTTP proxy settings:', '', '    Proxy Server(s) :  http=a:80;https=b:443', '    Bypass List     :  <local>;*.corp', '')
$de = @('', 'Aktuelle WinHTTP-Proxyeinstellungen:', '', '    Proxyserver:  proxy.corp:8080', '    Umgehungsliste:  (keine)', '')
$direct = @('', 'Current WinHTTP proxy settings:', '', '    Direct access (no proxy server).', '')
$n = Get-SherlogNetshProxy -Lines $en;     $r.enServer = $n.Server; $r.enBypass = $n.Bypass
$n = Get-SherlogNetshProxy -Lines $de;     $r.deServer = $n.Server
$n = Get-SherlogNetshProxy -Lines $direct; $r.directServer = $n.Server
$r.bypassLocal  = Test-SherlogProxyBypass -HostName 'intranet' -Bypass '<local>'
$r.bypassWild   = Test-SherlogProxyBypass -HostName 'sherlog.corp.local' -Bypass '<local>;*.corp.local'
$r.bypassMiss   = Test-SherlogProxyBypass -HostName 'sherlog.nl' -Bypass '<local>;*.corp.local'
$r.localhost    = Get-SherlogProxy -TargetUrl 'http://localhost:8080' -Explicit ''
$r.explicit     = Get-SherlogProxy -TargetUrl 'https://sherlog.nl' -Explicit 'http://p:1'
$r | ConvertTo-Json -Compress
""", script)
    assert out["perProto"] == "http://b.corp:443"
    assert out["httpOnly"] == "http://a.corp:80"
    assert out["plain"] == "http://proxy.corp:8080"
    assert out["withScheme"] == "http://proxy.corp:3128"
    assert out["socksOnly"] is None
    assert out["list"] == "http://p1:1"
    assert out["empty"] is None
    assert out["regServer"] == "http=a:80;https=b:443"
    assert out["regBypass"] == "<local>;*.corp.local"
    assert out["regDirect"] == ""
    assert out["regShort"] is True
    assert out["enServer"] == "http=a:80;https=b:443" and out["enBypass"] == "<local>;*.corp"
    assert out["deServer"] == "proxy.corp:8080"
    assert out["directServer"] == ""
    assert out["bypassLocal"] is True and out["bypassWild"] is True
    assert out["bypassMiss"] is False
    assert out["localhost"] is None
    assert out["explicit"] == "http://p:1"


# --- functional: misc helpers ----------------------------------------------------

@needs_pwsh
def test_anon_label_is_salted_hmac(tmp_path):
    out = run_ps(tmp_path, r"""
$salt = [byte[]](1..32)
@{ a = (Get-SherlogAnonLabel -ComputerName 'pc-0042' -Salt $salt)
   b = (Get-SherlogAnonLabel -ComputerName 'PC-0042' -Salt ([byte[]](2..33))) } | ConvertTo-Json -Compress
""")
    expected = hmac.new(bytes(range(1, 33)), b"PC-0042", hashlib.sha256).hexdigest()[:16]
    assert out["a"] == "anon-" + expected
    assert out["b"] != out["a"] and re.fullmatch(r"anon-[0-9a-f]{16}", out["b"])


@needs_pwsh
def test_protect_text_redacts_and_flattens(tmp_path):
    out = run_ps(tmp_path, rf"""
@{{ t = (Protect-SherlogText -Text "bad {TOKEN}`r`nnext line caf$([char]0xe9)" -Secret {ps_str(TOKEN)} -Max 24) }} |
    ConvertTo-Json -Compress
""", WRAPPER)
    assert out["t"] == "bad <redacted> next line..."


@needs_pwsh
def test_remove_tree_never_follows_links(tmp_path):
    target = tmp_path / "target"
    (target / "sub").mkdir(parents=True)
    (target / "keep.txt").write_text("keep")
    (target / "sub" / "deep.txt").write_text("keep")
    tree = tmp_path / "tree"
    (tree / "a" / "b").mkdir(parents=True)
    (tree / "a" / "b" / "file.txt").write_text("x")
    ro = tree / "a" / "readonly.txt"
    ro.write_text("x")
    ro.chmod(0o444)
    (tree / "dirlink").symlink_to(target, target_is_directory=True)
    (tree / "a" / "filelink").symlink_to(target / "keep.txt")
    (tree / "dangling").symlink_to(tmp_path / "does-not-exist")
    out = run_ps(tmp_path, rf"""
Remove-SherlogTree -Path {ps_str(str(tree))}
Remove-SherlogTree -Path {ps_str(str(tmp_path / 'never-existed'))}
@{{ ok = $true }} | ConvertTo-Json -Compress
""")
    assert out == {"ok": True}
    assert not tree.exists() and not tree.is_symlink()
    assert (target / "keep.txt").read_text() == "keep"
    assert (target / "sub" / "deep.txt").read_text() == "keep"


@needs_pwsh
def test_wrapper_throttle_and_backoff(tmp_path):
    out = run_ps(tmp_path, r"""
$now = [DateTime]::new(2026, 1, 10, 12, 0, 0, [DateTimeKind]::Utc)
function Stamp([double]$hoursAgo) { $now.AddHours(-$hoursAgo).ToString('o') }
function Decide($state) {
    $s = Get-SherlogSkipReason -State $state -Mode 'full' -NowUtc $now -MinHours 6
    if ($s) { "skip$($s.ExitCode)" } else { 'run' }
}
[ordered]@{
  none          = Decide $null
  empty         = Decide @{}
  recent        = Decide @{ LastRunUtc_full = (Stamp 2) }
  otherMode     = Decide @{ LastRunUtc_anon = (Stamp 2) }
  old           = Decide @{ LastRunUtc_full = (Stamp 7) }
  future        = Decide @{ LastRunUtc_full = (Stamp -30) }
  garbage       = Decide @{ LastRunUtc_full = 'not a date' }
  fail1Recent   = Decide @{ FailCount_full = 1; LastFailUtc_full = (Stamp 0.5) }
  fail1Old      = Decide @{ FailCount_full = 1; LastFailUtc_full = (Stamp 1.5) }
  fail3Recent   = Decide @{ FailCount_full = 3; LastFailUtc_full = (Stamp 3) }
  fail3Old      = Decide @{ FailCount_full = 3; LastFailUtc_full = (Stamp 4.5) }
  fail9Capped   = Decide @{ FailCount_full = 9; LastFailUtc_full = (Stamp 5) }
  fail9Old      = Decide @{ FailCount_full = 9; LastFailUtc_full = (Stamp 6.5) }
  failFuture    = Decide @{ FailCount_full = 2; LastFailUtc_full = (Stamp -5) }
} | ConvertTo-Json -Compress
""", WRAPPER)
    assert out == {
        "none": "run", "empty": "run", "recent": "skip0", "otherMode": "run",
        "old": "run", "future": "run", "garbage": "run",
        "fail1Recent": "skip1", "fail1Old": "run",          # 1 h after 1 failure
        "fail3Recent": "skip1", "fail3Old": "run",          # 4 h after 3 failures
        "fail9Capped": "skip1", "fail9Old": "run",          # capped at MinHours
        "failFuture": "run",
    }


@needs_pwsh
def test_copy_file_preserves_relative_layout(tmp_path):
    src = tmp_path / "src"
    (src / "sub").mkdir(parents=True)
    (src / "IntuneManagementExtension.log").write_text("top")
    (src / "sub" / "IntuneManagementExtension.log").write_text("nested")
    dest = tmp_path / "dest"
    run_ps(tmp_path, rf"""
foreach ($f in Get-ChildItem -LiteralPath {ps_str(str(src))} -File -Recurse) {{
    $rel = $f.FullName.Substring({ps_str(str(src))}.Length).TrimStart('\', '/')
    Copy-SherlogFile -Source $f.FullName -Destination (Join-Path {ps_str(str(dest))} $rel)
}}
'{{}}'
""")
    assert (dest / "IntuneManagementExtension.log").read_text() == "top"
    assert (dest / "sub" / "IntuneManagementExtension.log").read_text() == "nested"


# --- optional: PSScriptAnalyzer ------------------------------------------------

def _has_psscriptanalyzer() -> bool:
    if PWSH is None:
        return False
    r = subprocess.run([PWSH, "-NoProfile", "-NonInteractive", "-Command",
                        "if (Get-Module -ListAvailable PSScriptAnalyzer) { 'yes' }"],
                       capture_output=True, text=True, timeout=120)
    return "yes" in r.stdout


@pytest.mark.skipif(not _has_psscriptanalyzer(), reason="PSScriptAnalyzer not installed")
@pytest.mark.parametrize("script", SCRIPTS, ids=lambda p: p.name)
def test_psscriptanalyzer_clean(tmp_path, script):
    """Errors, plus the PS 5.1 compatibility rules (syntax, commands and
    parameters, .NET types against the Windows 10 / PS 5.1 profile).
    Style-only rules (Write-Host, empty catch, ShouldProcess) are not gated."""
    findings = run_ps(tmp_path, r"""
Import-Module PSScriptAnalyzer
$p51 = 'win-48_x64_10.0.17763.0_5.1.17763.316_x64_4.0.30319.42000_framework'
$settings = @{
    Rules = @{
        PSUseCompatibleSyntax   = @{ Enable = $true; TargetVersions = @('5.1') }
        PSUseCompatibleCommands = @{ Enable = $true; TargetProfiles = @($p51) }
        PSUseCompatibleTypes    = @{ Enable = $true; TargetProfiles = @($p51) }
    }
}
$gated = 'PSUseCompatibleSyntax', 'PSUseCompatibleCommands', 'PSUseCompatibleTypes',
         'PSUseDeclaredVarsMoreThanAssignments', 'PSPossibleIncorrectComparisonWithNull',
         'PSAvoidAssignmentToAutomaticVariable', 'PSAvoidUsingCmdletAliases',
         'PSUseCmdletCorrectly'
$all = @(Invoke-ScriptAnalyzer -Path $ScriptPath -Settings $settings) +
       @(Invoke-ScriptAnalyzer -Path $ScriptPath -IncludeRule $gated)
ConvertTo-Json -Compress -InputObject @($all | Where-Object { $_.Severity -eq 'Error' -or $gated -contains $_.RuleName } |
    ForEach-Object { "$($_.Line) $($_.RuleName): $($_.Message)" })
""", script)
    assert findings == []
