"""Living-off-the-Land behaviour detector — hunt_lotl_behaviors MCP tool.

Runs Chainsaw with Sigma rules against .evtx files, then cross-references
results against the LOLBAS catalogue. Covers ClickFix execution chains.

This is a new function — not present in marez8505/find-evil.
"""

import json
import re
from pathlib import Path
from parsers.common import run_tool, save_raw_output, tool_missing_response

# ── LOLBAS binary catalogue ────────────────────────────────────────────────
# Binaries documented at lolbas-project.github.io (Apache 2.0)
LOLBAS_BINARIES: set[str] = {
    "certutil.exe", "bitsadmin.exe", "mshta.exe", "regsvr32.exe",
    "powershell.exe", "wmic.exe", "schtasks.exe", "vssadmin.exe",
    "net.exe", "net1.exe", "wscript.exe", "cscript.exe", "rundll32.exe",
    "msiexec.exe", "cmd.exe", "forfiles.exe", "pcalua.exe", "bash.exe",
    "msbuild.exe", "installutil.exe", "regasm.exe", "regsvcs.exe",
    "csc.exe", "vbc.exe", "jsc.exe", "xwizard.exe", "dnscmd.exe",
    "esentutl.exe", "expand.exe", "extrac32.exe", "findstr.exe",
    "hh.exe", "ieexec.exe", "infdefaultinstall.exe", "makecab.exe",
    "mavinject.exe", "microsoft.workflow.compiler.exe", "msdeploy.exe",
    "msdt.exe", "msiexec.exe", "mspaint.exe", "odbcconf.exe",
    "pcwrun.exe", "replace.exe", "rpcping.exe", "runscripthelper.exe",
    "syncappvpublishingserver.exe", "tttracer.exe", "wab.exe",
    "winrm.cmd", "wsl.exe", "xsl.exe",
}

# ── Suspicious argument patterns per binary ────────────────────────────────
LOLBAS_PATTERNS: list[tuple[str, str, str, str, str]] = [
    # (binary, arg_pattern, reason, technique, stage)
    ("certutil.exe",  r"-(urlcache|decode|encode|f)",
     "certutil downloading or encoding file (common download cradle)",
     "T1105", "execution"),
    ("certutil.exe",  r"https?://",
     "certutil fetching URL",
     "T1105", "execution"),
    ("bitsadmin.exe", r"/(transfer|create|addfile|setnotifycmdline)",
     "BITSAdmin transfer job (persistent download cradle)",
     "T1197", "execution"),
    ("mshta.exe",     r"(https?://|vbscript:|javascript:)",
     "mshta executing remote or inline script",
     "T1218.005", "execution"),
    ("regsvr32.exe",  r"(/s.*scrobj|https?://|/u\s+/s)",
     "regsvr32 squiblydoo — remote COM scriptlet",
     "T1218.010", "execution"),
    ("wmic.exe",      r"(process\s+call\s+create|os\s+get|shadow)",
     "wmic process execution or shadow copy interaction",
     "T1047", "execution"),
    ("rundll32.exe",  r"javascript:|vbscript:|shell32\.dll.*shellexec",
     "rundll32 executing script via browser engine",
     "T1218.011", "execution"),
    ("powershell.exe",r"(-enc|-encodedcommand)",
     "Encoded PowerShell command (obfuscation)",
     "T1059.001", "execution"),
    ("powershell.exe",r"(IEX|Invoke-Expression).{0,50}(Net\.WebClient|webclient|http)",
     "PowerShell download cradle",
     "T1059.001", "execution"),
    ("vssadmin.exe",  r"delete\s+shadows",
     "VSS shadow copy deletion (ransomware/anti-forensic indicator)",
     "T1490", "impact"),
]

MAX_FINDINGS = 200


def hunt_lotl_behaviors(evtx_dir: str, output_dir: str,
                        sigma_rules_dir: str = "/opt/sigma") -> dict:
    """Detect Living-off-the-Land behaviours in Windows event logs.

    Pass 1 — Chainsaw: runs Sigma rules against all .evtx files in evtx_dir.
    Pass 2 — LOLBAS:   cross-references Chainsaw hits (and cmdline strings)
              against the LOLBAS catalogue with suspicious argument patterns.

    Args:
        evtx_dir:       Directory containing .evtx files
        output_dir:     Write directory for raw output (audit trail)
        sigma_rules_dir: Directory of Sigma rules for Chainsaw
                        (default /opt/sigma, installed by Chainsaw package)

    Returns:
        {
            tool, evtx_dir,
            chainsaw_hits: int,
            lolbas_hits:   int,
            findings: [ {binary, cmdline, event_id, time, reason,
                          mitre_technique, kill_chain_stage, confidence} ],
            error
        }
    """
    findings:  list[dict] = []
    errors:    list[str]  = []

    # ── Pass 1: Chainsaw ───────────────────────────────────────────────────
    chainsaw_hits = _run_chainsaw(evtx_dir, output_dir, sigma_rules_dir, findings, errors)

    # ── Pass 2: LOLBAS pattern scan on cmdline events ─────────────────────
    lolbas_hits = _run_lolbas_scan(evtx_dir, output_dir, findings, errors)

    # Deduplicate by (binary, cmdline[:80])
    seen:   set[tuple[str, str]] = set()
    unique: list[dict]           = []
    for f in findings:
        key = (f.get("binary", ""), f.get("cmdline", "")[:80])
        if key not in seen:
            seen.add(key)
            unique.append(f)

    return {
        "tool": "chainsaw+lolbas",
        "evtx_dir": evtx_dir,
        "chainsaw_hits": chainsaw_hits,
        "lolbas_hits": lolbas_hits,
        "findings_count": len(unique),
        "findings": unique[:MAX_FINDINGS],
        "error": "; ".join(errors) if errors else None,
    }


# ── Pass 1: Chainsaw ───────────────────────────────────────────────────────

def _run_chainsaw(
    evtx_dir:    str,
    output_dir:  str,
    sigma_dir:   str,
    findings:    list[dict],
    errors:      list[str],
) -> int:
    sigma_path = Path(sigma_dir)
    if not sigma_path.exists():
        # Try Chainsaw's bundled rules
        sigma_dir = "/opt/chainsaw/sigma"

    r = run_tool(
        ["chainsaw", "hunt", evtx_dir,
         "--sigma", sigma_dir,
         "--mapping", "/opt/chainsaw/mappings/sigma-event-logs-all.yml",
         "--output", output_dir,
         "--format", "json"],
        timeout=300,
    )

    if r["tool_missing"]:
        errors.append(
            "Chainsaw not found. Install: "
            "wget https://github.com/WithSecureLabs/chainsaw/releases/latest"
            "/download/chainsaw_x86_64-unknown-linux-gnu.tar.gz"
        )
        return 0

    save_raw_output(output_dir, "chainsaw_output.txt", r["stdout"])

    hit_count = 0
    chainsaw_json = Path(output_dir) / "chainsaw_results.json"
    raw = r["stdout"]

    # Chainsaw may write to file or stdout depending on version
    if chainsaw_json.exists():
        raw = chainsaw_json.read_text()

    for line in raw.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            hit = json.loads(line)
            findings.append({
                "source":          "chainsaw",
                "rule":            hit.get("name", hit.get("rule", "?")),
                "event_id":        hit.get("event_id", ""),
                "time":            hit.get("timestamp", ""),
                "binary":          _extract_binary(hit),
                "cmdline":         hit.get("cmdline", hit.get("data", {}).get("CommandLine", ""))[:300],
                "reason":          hit.get("name", "Sigma rule match"),
                "mitre_technique": hit.get("tags", ["T1059"])[0] if hit.get("tags") else "T1059",
                "kill_chain_stage":"execution",
                "confidence":      "high",
            })
            hit_count += 1
        except (json.JSONDecodeError, KeyError):
            continue

    return hit_count


# ── Pass 2: LOLBAS pattern scan ────────────────────────────────────────────

def _run_lolbas_scan(
    evtx_dir:   str,
    output_dir: str,
    findings:   list[dict],
    errors:     list[str],
) -> int:
    """Scan event-log cmdline strings for LOLBAS patterns."""
    # Use evtx_dump to get process creation events quickly
    hit_count = 0
    for evtx_file in Path(evtx_dir).rglob("*.evtx"):
        r = run_tool(["evtx_dump", "--format", "json", str(evtx_file)], timeout=60)
        if r["tool_missing"]:
            break
        if r["returncode"] != 0:
            continue

        for line in r["stdout"].splitlines():
            try:
                event = json.loads(line)
                eid = int(
                    event.get("Event", {}).get("System", {}).get("EventID", 0)
                )
                if eid != 4688:
                    continue

                data    = event.get("Event", {}).get("EventData", {})
                cmdline = (data.get("CommandLine") or data.get("NewProcessName") or "").lower()
                if not cmdline:
                    continue

                # Extract binary name
                binary = Path(cmdline.split()[0].strip('"')).name.lower() if cmdline else ""

                if binary not in LOLBAS_BINARIES:
                    continue

                for lol_bin, arg_re, reason, technique, stage in LOLBAS_PATTERNS:
                    if binary == lol_bin and re.search(arg_re, cmdline, re.IGNORECASE):
                        findings.append({
                            "source":           "lolbas",
                            "binary":           binary,
                            "cmdline":          cmdline[:300],
                            "event_id":         4688,
                            "time":             event.get("Event", {})
                                                     .get("System", {})
                                                     .get("TimeCreated", {})
                                                     .get("@SystemTime", ""),
                            "reason":           reason,
                            "mitre_technique":  technique,
                            "kill_chain_stage": stage,
                            "confidence":       "high",
                        })
                        hit_count += 1
                        break

            except (json.JSONDecodeError, ValueError, KeyError, IndexError):
                continue

    return hit_count


def _extract_binary(hit: dict) -> str:
    """Best-effort binary name extraction from a Chainsaw hit dict."""
    for key in ("NewProcessName", "CommandLine", "ImagePath", "Image"):
        val = hit.get(key) or hit.get("data", {}).get(key, "")
        if val:
            return Path(str(val).split()[0].strip('"')).name.lower()
    return "?"
