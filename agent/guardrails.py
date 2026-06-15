#!/usr/bin/env python3
"""
Find Evil! Hackathon — Guardrails Utility
==========================================
Three focused jobs:

  generate        Generate openclaw.json for a specific case directory
  check-injection Scan a string or file for prompt injection patterns
  gate            Confirmation prompt before an irreversible action
  mode            Show/set the exec-gateway profile (forensic|dev)
  require-stages  Fail-closed check that mandatory stages (incl. judge) ran
  summary         Write a plain-English summary of the active openclaw.json

Usage:
    python3 guardrails.py generate --case /cases/SRL-2015 [--out openclaw.json]
    python3 guardrails.py check-injection --string "ignore previous instructions..."
    python3 guardrails.py check-injection --file analysis/cmdline.txt
    python3 guardrails.py gate --action "write manifest.json"
    python3 guardrails.py require-stages --config openclaw.json
    python3 guardrails.py summary --config openclaw.json [--out guardrails_summary.md]

Exit codes:
    0  OK / clean / approved
    1  Injection detected / action denied / error
"""

import argparse
import json
import os
import re
import sys
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path

GATEWAY_URL = "http://127.0.0.1:12345"
AGENT_ACTIVITY_LOG = Path(os.environ.get("AGENT_ACTIVITY_LOG",
                                         "/home/la/analysis/agent_activity.log"))


def _gw_post(path, payload):
    """POST JSON to the exec gateway with the gateway token. Returns (code, body)."""
    token = ""
    try:
        token = Path("/cases/project/.gateway_token").read_text().strip()
    except Exception:
        pass
    req = urllib.request.Request(
        GATEWAY_URL + path, data=json.dumps(payload).encode(), method="POST",
        headers={"Content-Type": "application/json", "X-Gateway-Token": token})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read())
        except Exception:
            return e.code, {"reason": str(e)}
    except Exception as e:  # noqa: BLE001
        return 0, {"reason": f"gateway unreachable: {e}"}

# ---------------------------------------------------------------------------
# Prompt injection patterns
# Each entry: (pattern_regex, description, severity)
# Severity: HIGH = almost certainly adversarial, MEDIUM = suspicious
# ---------------------------------------------------------------------------
INJECTION_PATTERNS = [
    # Direct override attempts
    (r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?|directives?)",
     "Instruction override attempt", "HIGH"),
    (r"disregard\s+(all\s+)?(previous|prior|above)",
     "Instruction disregard attempt", "HIGH"),
    (r"forget\s+(everything|all|your\s+instructions?|what\s+you\s+(were|have\s+been)\s+told)",
     "Instruction reset attempt", "HIGH"),
    (r"you\s+are\s+now\s+(a\s+)?(different|new|another|evil|unrestricted|jailbroken)",
     "Persona replacement attempt", "HIGH"),
    (r"(pretend|act|roleplay|imagine)\s+(you\s+are|that\s+you\s+are|to\s+be)\s+(a\s+)?(different|evil|hacker|uncensored|unrestricted|DAN|jailbroken)",
     "Adversarial persona injection", "HIGH"),
    (r"\bDAN\b.*?(do\s+anything\s+now|jailbreak)",
     "DAN jailbreak pattern", "HIGH"),
    (r"(your\s+)?(new\s+)?(system\s+prompt|instructions?\s+are|role\s+is)\s*[:=]",
     "System prompt replacement attempt", "HIGH"),
    (r"(reveal|show|print|output|display|repeat)\s+(your\s+)?(system\s+prompt|instructions?|rules?|directives?|context)",
     "System prompt exfiltration attempt", "HIGH"),
    (r"</?(system|instructions?|prompt|context|human|assistant|user)>",
     "Injected XML/tag delimiter", "HIGH"),
    (r"\[INST\]|\[\/INST\]|\[SYSTEM\]|\[\/SYSTEM\]",
     "Injected instruction-format delimiter", "HIGH"),
    # Indirect manipulation
    (r"(translate|convert|encode|decode)\s+.{0,30}(instructions?|rules?)\s+to",
     "Indirect instruction manipulation", "MEDIUM"),
    (r"(base64|hex|rot13|caesar)\s+(encode|decode|encoded|decoded)\s+(instructions?|payload|command)",
     "Encoded payload delivery attempt", "MEDIUM"),
    (r"(execute|run|eval)\s+(this|the\s+following)\s+(code|script|command|payload)",
     "Code execution injection", "HIGH"),
    (r"(sudo|chmod|chown|rm\s+-rf|mkfs|dd\s+if=)\s",
     "Dangerous shell command in evidence string", "HIGH"),
    (r"curl\s+.{0,60}(bash|sh|python|perl|ruby)\s*\|",
     "Remote code execution via pipe", "HIGH"),
    (r"wget\s+.{0,60}-O\s*-\s*\|",
     "Remote code execution via wget pipe", "HIGH"),
    # Boundary confusion
    (r"(end\s+of\s+evidence|evidence\s+ends?\s+here|analyst\s+note|forensic\s+note)\s*[:;]",
     "Evidence/instruction boundary confusion", "MEDIUM"),
    (r"(note\s+to\s+(analyst|agent|claude|ai)|important\s+for\s+(analyst|agent|claude|ai))\s*:",
     "Embedded instruction masquerading as note", "MEDIUM"),
    # Token smuggling / unusual encoding
    (r"[\u200b\u200c\u200d\u2060\ufeff]",
     "Zero-width / invisible Unicode characters (token smuggling)", "HIGH"),
    (r"[\u202a-\u202e\u2066-\u2069]",
     "Unicode bidirectional override characters", "HIGH"),
]

_COMPILED = [(re.compile(p, re.IGNORECASE | re.UNICODE), desc, sev)
             for p, desc, sev in INJECTION_PATTERNS]


# ---------------------------------------------------------------------------
# Subcommand: check-injection
# ---------------------------------------------------------------------------
def cmd_check_injection(args):
    if args.string:
        text = args.string
        source = "<command-line string>"
    elif args.file:
        fp = Path(args.file)
        if not fp.exists():
            print(f"[ERROR] File not found: {fp}", file=sys.stderr)
            sys.exit(1)
        text = fp.read_text(errors="replace")
        source = str(fp)
    else:
        # Read from stdin
        text = sys.stdin.read()
        source = "<stdin>"

    hits = []
    for pattern, desc, sev in _COMPILED:
        for m in pattern.finditer(text):
            hits.append({
                "pattern":   desc,
                "severity":  sev,
                "match":     m.group(0)[:120],
                "offset":    m.start(),
                "source":    source,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })

    if hits:
        print(f"[INJECTION DETECTED] {len(hits)} pattern(s) matched in: {source}",
              file=sys.stderr)
        for h in hits:
            print(f"  [{h['severity']}] {h['pattern']}", file=sys.stderr)
            print(f"           match: {repr(h['match'])}", file=sys.stderr)
            print(f"           offset: {h['offset']}", file=sys.stderr)

        if args.json:
            print(json.dumps(hits, indent=2))

        sys.exit(1)   # exit 1 = injection detected
    else:
        if args.verbose:
            print(f"[OK] No injection patterns detected in: {source}")
        sys.exit(0)   # exit 0 = clean


# ---------------------------------------------------------------------------
# Subcommand: generate
# ---------------------------------------------------------------------------
def cmd_generate(args):
    case_dir = Path(args.case).resolve()
    out_path = Path(args.out) if args.out else Path("openclaw.json")

    config = {
        "_comment": (
            "Exec gateway configuration — generated by guardrails.py. "
            "Enforced by runclawd_exec_gateway.py running as a separate process. "
            "Do not lower any deny rule without a documented reason."
        ),
        "gateway": {
            "host":  "127.0.0.1",
            "port":  12345,
            "token_file": "/cases/project/.gateway_token",
            "start_cmd": "python3 /cases/project/runclawd_exec_gateway.py"
        },
        "security": {
            "fileSystem": {
                "allowRead": [
                    str(case_dir / "evidence") + "/",
                    str(case_dir / "analysis") + "/",
                    "/cases/project/",
                    "/tmp/",
                ],
                "allowWrite": [
                    str(case_dir / "analysis") + "/",
                    str(case_dir / "reports") + "/",
                    "/tmp/",
                ],
                "denyWrite": [
                    str(case_dir / "evidence") + "/",
                    "/etc/",
                    "/usr/",
                    "/bin/",
                    "/sbin/",
                    str(Path.home() / ".bashrc"),
                    str(Path.home() / ".profile"),
                    "/cases/project/MEMORY.md",
                    str(case_dir / "analysis" / "findings_log.json") + ":direct",
                    # findings_log must be updated via append, never truncated
                ]
            },
            "exec": {
                "mode": "allowlist",
                "allow": [
                    "vol", "volatility3",
                    "log2timeline.py", "psort.py",
                    "fls", "icat", "fsstat",
                    "bulk_extractor",
                    "evtx_dump",
                    "yara",
                    "chainsaw",
                    "python3",
                    "tshark",
                    "sha256sum",
                    "git",
                    "cat", "ls", "find", "jq", "grep",
                    "file", "strings", "xxd",
                    "curl",   # only to localhost:3000 (health check) — OpenClaw enforces this
                    "id",     # pre-flight check
                ],
                "deny": [
                    "rm -rf",
                    "mkfs",
                    "dd",
                    "chmod 777",
                    "sudo",
                    "su",
                    "wget",
                    "nc", "netcat", "ncat",
                    "bash -i",
                    "python3 -c",    # inline exec — use script files only
                ]
            },
            "network": {
                "allowOutbound": [
                    "127.0.0.1:3000"   # OpenClaw gateway only
                ],
                "denyOutbound": ["*"]  # ufw handles this at OS level; belt-and-suspenders here
            }
        },
        "process": {
            "_comment": (
                "Mandatory pipeline stages — enforced OUTSIDE agent discretion and "
                "fail-closed. The agent may not skip these even if it judges skipping "
                "optimal. Judge review is enforced at the findings-commit path in "
                "runclawd_exec_gateway.py (POST /commit-findings); stage completion is "
                "verified by `guardrails.py require-stages` before any report is built."
            ),
            "enforcement": "fail-closed",
            "mandatoryStages": [
                "manifest_before_analysis",
                "evidence_reads_via_mcp",
                "judge_review_each_finding",
            ],
            "judge": {
                "required": True,
                "appliesTo": "every finding",
                "requiredFields": ["judge_reviewed", "judge_verdict"],
                "commitableVerdicts": ["confirmed", "flagged"],
                "onMissing": "reject",
            },
            "stageLedger":  str(case_dir / "analysis" / "pipeline_stages.json"),
            "findingsPath": str(case_dir / "analysis" / "findings_log.json"),
        },
        "generated_at":  datetime.now(timezone.utc).isoformat(),
        "generated_by":  "guardrails.py",
        "case_dir":      str(case_dir),
    }

    out_path.write_text(json.dumps(config, indent=2))
    print(f"[OK] exec gateway config written to: {out_path}")
    print(f"     Case dir  : {case_dir}")
    print(f"     Allow read: {case_dir}/evidence/, {case_dir}/analysis/, /cases/project/")
    print(f"     Allow write: {case_dir}/analysis/, {case_dir}/reports/")
    print(f"     Deny write: evidence/, /etc/, /usr/, MEMORY.md, findings_log.json (direct)")
    print(f"     Exec mode : allowlist ({len(config['security']['exec']['allow'])} allowed)")
    print(f"     Gateway   : http://127.0.0.1:12345")
    print(f"     Start cmd : python3 /cases/project/runclawd_exec_gateway.py")
    print(f"     Process   : fail-closed — judge required on every finding; "
          f"mandatory stages: {', '.join(config['process']['mandatoryStages'])}")


# ---------------------------------------------------------------------------
# Subcommand: gate
# ---------------------------------------------------------------------------
def cmd_gate(args):
    action = args.action or "(action not specified)"
    print()
    print("╔══════════════════════════════════════════════════════╗")
    print("║              CONFIRMATION REQUIRED                   ║")
    print("╚══════════════════════════════════════════════════════╝")
    print(f"  Proposed action: {action}")
    print()
    print("  This action may be irreversible.")
    print("  Type CONFIRM to proceed, anything else to abort:")
    print()

    # In automated / non-interactive mode (stdin is not a tty), deny by default
    if not sys.stdin.isatty():
        print("[GATE] Non-interactive mode — action denied for safety.", file=sys.stderr)
        sys.exit(1)

    try:
        response = input("  > ").strip()
    except (EOFError, KeyboardInterrupt):
        print("\n[GATE] Aborted.", file=sys.stderr)
        sys.exit(1)

    if response == "CONFIRM":
        print(f"[GATE] Approved: {action}")
        # Log the approval
        log_path = Path("analysis/tool_errors.log")
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with log_path.open("a") as f:
            f.write(
                f"{datetime.now(timezone.utc).isoformat()} [GATE APPROVED] {action}\n"
            )
        sys.exit(0)
    else:
        print(f"[GATE] Denied — action not confirmed.", file=sys.stderr)
        sys.exit(1)


# ---------------------------------------------------------------------------
# Subcommand: mode  (exec-gateway profile toggle)
# ---------------------------------------------------------------------------
def cmd_mode(args):
    """Show or set the exec-gateway profile: 'forensic' (default, case data is
    MCP-only) or 'dev' (permissive, for /cases/project tooling work).

    Integrity-first: dev is a deliberate, temporary switch. When the toggle is on
    (forensic) and an investigation is running, case data is touched only via the
    sift-ir-agent MCP server; if that leaves a gap, switch to dev, fix the tooling,
    then return to forensic and rerun the investigation."""
    mode_file = Path(args.file)
    if args.set:
        rec = {"mode": args.set,
               "set_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
               "set_by": "guardrails.py"}
        mode_file.write_text(json.dumps(rec))
        print(f"[OK] exec gateway mode -> {args.set}   ({mode_file})")
        if args.set == "dev":
            print("     WARNING: dev enables curl/bash/rm and direct case-path access.")
            print("     Switch back to forensic before resuming or rerunning the investigation.")
        sys.exit(0)
    # show — fail-closed to forensic
    mode = "forensic"
    if mode_file.exists():
        try:
            raw = mode_file.read_text().strip()
            mode = (json.loads(raw).get("mode") if raw.startswith("{") else raw) or "forensic"
        except Exception:
            mode = "forensic"
    mode = "dev" if mode == "dev" else "forensic"
    print(f"exec gateway mode: {mode}   ({mode_file})")
    sys.exit(0)


# ---------------------------------------------------------------------------
# Subcommand: commit  (sanctioned dashboard-artifact write via the gateway)
# ---------------------------------------------------------------------------
def cmd_commit(args):
    """Write a dashboard artifact through the exec gateway — the sanctioned write
    path that works in forensic mode without touching a case dir directly.

    The case is passed by NAME (e.g. SRL-2015), never as a /cases/<case> path, so
    the command itself passes forensic validation; the gateway resolves the path."""
    raw = Path(args.from_).read_text() if args.from_ else sys.stdin.read()
    try:
        content = json.loads(raw)
    except Exception as e:  # noqa: BLE001
        print(f"[ERROR] input is not valid JSON: {e}", file=sys.stderr)
        sys.exit(1)
    case_name = os.path.basename(args.case.rstrip("/"))   # accept name or path, use name
    if args.kind == "findings":
        code, body = _gw_post("/commit-findings", {
            "caller": "guardrails.py", "case": case_name,
            "findings": content, "mode": args.mode})
    else:
        code, body = _gw_post("/commit-artifact", {
            "caller": "guardrails.py", "case": case_name,
            "kind": args.kind, "content": content})
    print(f"[{code}] {json.dumps(body)}")
    sys.exit(0 if code == 200 else 1)


# ---------------------------------------------------------------------------
# Subcommand: activity  (emit semantic agent-activity events for the dashboard)
# ---------------------------------------------------------------------------
def cmd_activity(args):
    """Append semantic agent-activity event(s) to the agent-activity ledger that the
    dashboard's Agent Activity panel reads — phases, judge decisions, enrichment, etc.
    Either --event/--detail (single) or --from <JSON array of {event,detail}> (batch)."""
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if args.from_:
        try:
            data = json.loads(Path(args.from_).read_text())
        except Exception as e:  # noqa: BLE001
            print(f"[ERROR] {e}", file=sys.stderr); sys.exit(1)
        events = data if isinstance(data, list) else []
    elif args.event:
        events = [{"event": args.event, "detail": args.detail or ""}]
    else:
        print("[ERROR] provide --event or --from", file=sys.stderr); sys.exit(1)
    AGENT_ACTIVITY_LOG.parent.mkdir(parents=True, exist_ok=True)
    with AGENT_ACTIVITY_LOG.open("a") as f:
        for e in events:
            f.write(json.dumps({"ts": e.get("ts", ts), "action": "activity",
                                "event": str(e.get("event", "")),
                                "detail": str(e.get("detail", ""))}) + "\n")
    print(f"[OK] logged {len(events)} activity event(s) -> {AGENT_ACTIVITY_LOG}")
    sys.exit(0)


# ---------------------------------------------------------------------------
# Subcommand: require-stages
# ---------------------------------------------------------------------------
def cmd_require_stages(args):
    """Fail-closed verification that the agreed pipeline stages actually ran.

    Exits 1 (blocking) if any mandatory stage is missing — including judge review
    of EVERY finding. This is the gate that makes the judge non-optional: it does
    not matter whether the agent judged skipping a stage 'optimal', the report
    pipeline cannot proceed past a missing stage. Mirrors cmd_gate's deny-by-default.
    """
    cfg_path = Path(args.config)
    if not cfg_path.exists():
        print(f"[ERROR] Config not found: {cfg_path}", file=sys.stderr)
        sys.exit(1)
    proc = json.loads(cfg_path.read_text()).get("process", {})
    if not proc:
        print("[REQUIRE-STAGES] No 'process' block in config — fail-closed. "
              "Regenerate openclaw.json with `guardrails.py generate`.", file=sys.stderr)
        sys.exit(1)

    mandatory = list(proc.get("mandatoryStages", []))
    judge     = proc.get("judge", {})
    findings_path = Path(args.findings or proc.get("findingsPath", ""))
    ledger_path   = Path(args.ledger   or proc.get("stageLedger", ""))
    failures = []

    # 1) Judge applied to EVERY finding (the non-optional rule)
    if "judge_review_each_finding" in mandatory or judge.get("required"):
        if not str(findings_path) or not findings_path.exists():
            failures.append(f"findings file missing: {findings_path}")
        else:
            try:
                findings = json.loads(findings_path.read_text())
            except Exception as e:  # noqa: BLE001
                findings = None
                failures.append(f"findings unreadable: {e}")
            if isinstance(findings, list):
                req = judge.get("requiredFields", ["judge_reviewed", "judge_verdict"])
                commitable = set(judge.get("commitableVerdicts", ["confirmed", "flagged"]))
                for i, f in enumerate(findings):
                    if not isinstance(f, dict):
                        failures.append(f"finding[{i}] is not an object"); continue
                    missing = [k for k in req if not f.get(k)]
                    if missing:
                        failures.append(f"finding[{i}] missing judge field(s) {missing}: "
                                        f"{str(f.get('finding',''))[:60]!r}")
                    elif commitable and f.get("judge_verdict") not in commitable:
                        failures.append(f"finding[{i}] verdict {f.get('judge_verdict')!r} not committable")

    # 2) Other mandatory stages must be recorded in the stage ledger
    other = [s for s in mandatory if s != "judge_review_each_finding"]
    if other:
        recorded = set()
        if str(ledger_path) and ledger_path.exists():
            try:
                data = json.loads(ledger_path.read_text())
                if isinstance(data, list):
                    recorded = {d.get("stage") if isinstance(d, dict) else d for d in data}
                elif isinstance(data, dict):
                    recorded = set(data.keys())
            except Exception as e:  # noqa: BLE001
                failures.append(f"stage ledger unreadable: {e}")
        else:
            failures.append(f"stage ledger missing: {ledger_path} (cannot prove stages ran)")
        for s in other:
            if s not in recorded:
                failures.append(f"mandatory stage not recorded: {s}")

    if failures:
        print(f"[REQUIRE-STAGES] FAIL ({len(failures)}) — pipeline integrity not satisfied:",
              file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        try:
            lp = Path("analysis/tool_errors.log")
            lp.parent.mkdir(parents=True, exist_ok=True)
            with lp.open("a") as fh:
                fh.write(f"{datetime.now(timezone.utc).isoformat()} "
                         f"[REQUIRE-STAGES DENIED] {len(failures)} failure(s)\n")
        except Exception:
            pass
        sys.exit(1)

    print(f"[REQUIRE-STAGES] OK — judge applied to every finding; "
          f"stages satisfied: {', '.join(mandatory)}")
    sys.exit(0)


# ---------------------------------------------------------------------------
# Subcommand: summary
# ---------------------------------------------------------------------------
def cmd_summary(args):
    config_path = Path(args.config)
    if not config_path.exists():
        print(f"[ERROR] Config not found: {config_path}", file=sys.stderr)
        sys.exit(1)

    cfg = json.loads(config_path.read_text())
    sec  = cfg.get("security", {})
    fs   = sec.get("fileSystem", {})
    ex   = sec.get("exec", {})
    net  = sec.get("network", {})
    proc = cfg.get("process", {})
    jud  = proc.get("judge", {})

    lines = [
        "# Guardrails Summary",
        "",
        f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        f"Config:    {config_path}",
        f"Case:      {cfg.get('case_dir', 'unknown')}",
        "",
        "## File System",
        "",
        "**Allowed to read:**",
    ]
    for p in fs.get("allowRead", []):
        lines.append(f"- `{p}`")

    lines += ["", "**Allowed to write:**"]
    for p in fs.get("allowWrite", []):
        lines.append(f"- `{p}`")

    lines += ["", "**denyWrite — hard blocks:**"]
    for p in fs.get("denyWrite", []):
        lines.append(f"- `{p}`")

    lines += [
        "",
        "## Execution",
        "",
        f"Mode: **{ex.get('mode', 'unknown')}**",
        "",
        "**Allowed tools:**",
        ", ".join(f"`{t}`" for t in ex.get("allow", [])),
        "",
        "**Denied commands:**",
        ", ".join(f"`{t}`" for t in ex.get("deny", [])),
        "",
        "## Network",
        "",
        "**Allowed outbound:** " + ", ".join(net.get("allowOutbound", ["none"])),
        "**Denied outbound:** all other destinations",
        "",
        "## Mandatory process (fail-closed)",
        "",
        f"Enforcement: **{proc.get('enforcement', 'n/a')}**",
        "Mandatory stages: " + (", ".join(f"`{s}`" for s in proc.get("mandatoryStages", [])) or "none"),
        f"Judge: required on **{jud.get('appliesTo', 'n/a')}** — fields "
        f"{jud.get('requiredFields', [])}, committable verdicts {jud.get('commitableVerdicts', [])}.",
        "Enforced at: `runclawd_exec_gateway.py` POST `/commit-findings` (write path) "
        "and `guardrails.py require-stages` (fail-closed gate before reporting).",
        "",
        "## Injection detection",
        "",
        f"Active patterns: {len(INJECTION_PATTERNS)}",
        "Run `python3 guardrails.py check-injection --string <text>` to scan any string.",
        "",
        "## Notes",
        "",
        "- Evidence directory is read-only at the OS level (chmod 444) AND blocked by this config.",
        "- findings_log.json must be updated via append — direct truncation is blocked.",
        "- Judge review is mandatory on every finding and enforced at the gateway commit path — the agent cannot skip it, even if it judges skipping optimal.",
        "- OpenClaw minimum version: 2026.2.25 (CVE-2026-25253 security floor).",
    ]

    out_path = Path(args.out) if args.out else Path("guardrails_summary.md")
    out_path.write_text("\n".join(lines) + "\n")
    print(f"[OK] Summary written to: {out_path}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Find Evil! IR Agent — Guardrails Utility",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # generate
    p_gen = sub.add_parser("generate", help="Generate openclaw.json for a case directory")
    p_gen.add_argument("--case", required=True, help="Case root directory (e.g. /cases/SRL-2015)")
    p_gen.add_argument("--out",  default="openclaw.json", help="Output path (default: openclaw.json)")

    # check-injection
    p_inj = sub.add_parser("check-injection", help="Scan text for prompt injection patterns")
    grp = p_inj.add_mutually_exclusive_group()
    grp.add_argument("--string", help="String to scan")
    grp.add_argument("--file",   help="File to scan")
    p_inj.add_argument("--json",    action="store_true", help="Output hits as JSON to stdout")
    p_inj.add_argument("--verbose", action="store_true", help="Print OK message when clean")

    # gate
    p_gate = sub.add_parser("gate", help="Confirmation gate for irreversible actions")
    p_gate.add_argument("--action", required=True, help="Description of the proposed action")

    # mode
    p_mode = sub.add_parser("mode", help="Show/set exec-gateway profile (forensic|dev)")
    p_mode.add_argument("--set", choices=["dev", "forensic"], help="Set the mode")
    p_mode.add_argument("--file", default="/cases/project/.gateway_mode",
                        help="Mode file (default: /cases/project/.gateway_mode)")

    # commit
    p_commit = sub.add_parser("commit", help="Sanctioned dashboard-artifact write via the gateway")
    p_commit.add_argument("--kind", required=True,
                          choices=["findings", "theory", "coverage", "accuracy", "manifest"])
    p_commit.add_argument("--case", required=True, help="Case name or path, e.g. SRL-2015")
    p_commit.add_argument("--from", dest="from_", help="JSON file to read (default: stdin)")
    p_commit.add_argument("--mode", default="replace", choices=["replace", "append"],
                          help="findings write mode (replace|append)")

    # activity
    p_act = sub.add_parser("activity", help="Log semantic agent-activity event(s) for the dashboard")
    p_act.add_argument("--event", help="Event label (e.g. judge, phase, enrich)")
    p_act.add_argument("--detail", help="Event detail text")
    p_act.add_argument("--from", dest="from_", help="JSON array of {event,detail} to batch-append")

    # require-stages
    p_req = sub.add_parser("require-stages",
                           help="Fail-closed check that mandatory stages (incl. judge on every finding) ran")
    p_req.add_argument("--config", default="openclaw.json", help="openclaw.json with the process block")
    p_req.add_argument("--findings", help="findings_log.json (default: config process.findingsPath)")
    p_req.add_argument("--ledger", help="stage ledger json (default: config process.stageLedger)")

    # summary
    p_sum = sub.add_parser("summary", help="Write a plain-English summary of the active config")
    p_sum.add_argument("--config", default="openclaw.json", help="Config file to summarise")
    p_sum.add_argument("--out", default="guardrails_summary.md", help="Output markdown path")

    args = parser.parse_args()

    dispatch = {
        "generate":        cmd_generate,
        "check-injection": cmd_check_injection,
        "gate":            cmd_gate,
        "mode":            cmd_mode,
        "commit":          cmd_commit,
        "activity":        cmd_activity,
        "require-stages":  cmd_require_stages,
        "summary":         cmd_summary,
    }
    dispatch[args.command](args)


if __name__ == "__main__":
    main()
