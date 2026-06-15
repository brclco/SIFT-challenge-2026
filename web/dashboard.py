#!/usr/bin/env python3
"""
Find Evil! Hackathon — IR Agent Live Dashboard
================================================
Reads findings_log.json and case_theory.json in real time and
renders a dark-themed 3-panel web dashboard.

Usage:
    python3 dashboard.py
    python3 dashboard.py --case /cases/SRL-2015 --port 5000
    python3 dashboard.py --host 0.0.0.0        # LAN access (split-screen demo)

Requires:
    pip install flask --break-system-packages

Expected file layout (relative to --case dir):
    <case>/analysis/findings_log.json    — list of finding objects
    <case>/analysis/case_theory.json     — narrative + overall_intent from Component 3a

findings_log.json schema (one object per finding):
{
  "timestamp":      "2026-06-01T14:23:11Z",
  "finding":        "Lateral movement via pass-the-hash",
  "artifact":       "/cases/SRL-2015/evidence/Security.evtx",
  "offset":         4821,
  "tool":           "evtx_dump",
  "confidence":     "high",            // high | medium | low
  "mitre_technique":"T1550.002",
  "kill_chain_stage":"lateral-movement",
  "intent_class":   "MALICE",          // MALICE | SUSPICION | NEGLIGENCE
  "ai_enriched":    true,
  "ai_model":       "claude-sonnet-4-6",
  "judge_review":   false,             // true = judging LLM flagged this finding
  "self_correction":false              // true = agent corrected itself to reach this finding
}

case_theory.json schema (written by Component 3a watcher):
{
  "overall_intent":  "MALICE",
  "narrative":       "Attacker gained initial access via ...",
  "mitre_techniques":["T1190", "T1053", "T1550.002"],
  "updated_at":      "2026-06-01T14:25:00Z"
}
"""

import argparse
import json
import os
import re
import subprocess
import sys
import urllib.request
from datetime import datetime
from pathlib import Path

try:
    from flask import Flask, jsonify, render_template_string, request
except ImportError:
    print("Flask not found. Install with:  pip install flask --break-system-packages")
    sys.exit(1)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
# Full ATT&CK Enterprise tactic set (14), in canonical order. Internal keys map
# 1:1 to the official tactic names so findings light up the correct stage.
KILL_CHAIN_ORDER = [
    ("reconnaissance",       "Reconnaissance"),
    ("resource-development", "Resource Development"),
    ("initial-access",       "Initial Access"),
    ("execution",            "Execution"),
    ("persistence",          "Persistence"),
    ("privilege-escalation", "Privilege Escalation"),
    ("defense-evasion",      "Defense Evasion"),
    ("credential-access",    "Credential Access"),
    ("discovery",            "Discovery"),
    ("lateral-movement",     "Lateral Movement"),
    ("collection",           "Collection"),
    ("command-and-control",  "Command and Control"),
    ("exfiltration",         "Exfiltration"),
    ("impact",               "Impact"),
]

# ---------------------------------------------------------------------------
# Data helpers
# ---------------------------------------------------------------------------
def _load_json(path: Path):
    """Return parsed JSON or None — never raises."""
    try:
        if path.exists():
            return json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        pass
    return None


def load_findings(analysis_dir: Path):
    data = _load_json(analysis_dir / "findings_log.json")
    return data if isinstance(data, list) else []


def load_theory(analysis_dir: Path):
    return _load_json(analysis_dir / "case_theory.json") or {}


def load_accuracy(analysis_dir: Path):
    return _load_json(analysis_dir / "accuracy_report.json") or {}


# ---------------------------------------------------------------------------
# Entity extraction (OS-agnostic) — see ENTITIES.md for rules + sources.
# Indexes findings by the discrete entities they reference, for navigation only.
# Categories with no discrete, validatable identifier stay empty by design.
# ---------------------------------------------------------------------------
# Identities: user-profile roots across OSes/eras — Windows long form
# ("Documents and Settings", "Users"), Windows 8.3 short form as emitted by XP
# precooked tools (DOCUME~1, USERS~1), and Linux user-bearing paths (/home plus
# per-user mail/cron under FHS) — followed by the account name. Plus SIDs with
# RID >= 1000 (real users; built-ins are RID < 1000).
_RE_USER_PATH = re.compile(
    r'(?:Documents and Settings|DOCUME~\d+|Users|USERS~\d+|/home'
    r'|/var/spool/mail|/var/mail|/var/spool/cron/crontabs)[\\/]+([A-Za-z][\w.$-]{1,31})', re.I)
_RE_IPV4 = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b')
_RE_SID_USER  = re.compile(r'\bS-1-5-21-\d+-\d+-\d+-(\d+)\b')
_RE_SID_FULL  = re.compile(r'\bS-1-5-21-\d+-\d+-\d+-\d+\b')
_RE_REG       = re.compile(r'\bHK(?:LM|CU|U|CR|CC|EY_[A-Z_]+)\\[^\s",;)\]]+', re.I)
_RE_FILE      = re.compile(r'\b[\w.$~-]+\.(?:exe|dll|sys|drv|scr|com|bat|cmd|ps1|psm1|vbs|vbe|js|jse|wsf|hta|jar|msi|ocx|cpl|py|sh|so|ko|elf|bin|dat|tmp|lnk)\b', re.I)
# Executable IMAGES that run as a process (subset of files — excludes libraries/
# drivers/data: dll, sys, so, ko, dat, …). Used to also surface processes named
# only in finding text (e.g. "via process 'jusched.exe'").
_RE_PROC      = re.compile(r'\b[\w.$~-]+\.(?:exe|scr|com|pif|bat|cmd|ps1|psm1|vbs|vbe|js|jse|wsf|hta|jar|py|sh|elf|run)\b', re.I)
_RE_THUMB     = re.compile(r'\b[0-9A-Fa-f]{40}\b')
_RE_CN        = re.compile(r'\bCN\s*=\s*([^,;/\n]+)')
_RE_CERTFILE  = re.compile(r'\b[\w.$-]+\.(?:cer|crt|pfx|p12|pem|der)\b', re.I)
_RE_LOGON     = re.compile(r'(?:Logon\s*ID|Session\s*ID)\s*[:=]?\s*(0x[0-9A-Fa-f]+|\d{3,})', re.I)

# Built-in / pseudo accounts and path keywords that are not real identities.
_NON_USERS = {
    "all users", "default user", "default", "public", "localservice", "local service",
    "networkservice", "network service", "local settings", "localsettings", "temp", "tmp",
    "systemprofile", "ntuser", "system", "administrator", "guest", "defaultaccount",
    "wdagutilityaccount", "application data", "appdata", "root", "daemon", "bin", "sys",
    "nobody", "sync", "games", "man", "lp", "mail", "news", "uucp", "proxy", "www-data",
    "backup", "list", "irc", "gnats", "systemd-network", "messagebus", "sshd",
    # 8.3 short names of system profile folders (not real users)
    "alluse~1", "defaul~1", "locals~1", "networ~1", "applic~1", "ntuser~1",
}
# Trailing acquisition descriptors stripped from an evidence dir to get the host.
_IMG_SUFFIXES = ("c-drive", "d-drive", "e-drive", "memory", "mem", "ram", "disk", "image",
                 "raw", "dd", "e01", "ewf", "vmdk", "vhd", "vhdx", "pagefile", "hiberfil", "drive")


def _finding_key(f):
    """Match the client's fKey(): timestamp + '|' + finding[:48]."""
    return (f.get("timestamp") or "") + "|" + (f.get("finding") or "")[:48]


def _host_of(f):
    a = f.get("artifact") or ""
    i = a.find("/evidence/")
    if i < 0:
        return f.get("host") or "unknown"
    seg = a[i + len("/evidence/"):].split("/")[0]
    low = seg.lower()
    for suf in _IMG_SUFFIXES:
        if low.endswith("-" + suf):
            seg = seg[: -(len(suf) + 1)]
            break
    return seg or "unknown"


def _looks_like_path(s):
    return bool(s) and ("/" in s or "\\" in s or bool(re.search(r'\.\w{1,5}$', s)))


def extract_entities(findings):
    cats = {k: {} for k in
            ("identities", "hosts", "network", "files", "processes",
             "registry_keys", "certificates", "sessions")}

    def add(cat, name, fk, host=None, dedup_ci=True, **extra):
        name = (name or "").strip()
        if not name:
            return
        ekey = (host or "", name.lower() if dedup_ci else name)
        slot = cats[cat].get(ekey)
        if not slot:
            slot = {"name": name, "keys": set()}
            if host is not None:
                slot["host"] = host
            cats[cat][ekey] = slot
        for k, v in extra.items():          # fill extras (e.g. parent) when known
            if v and not slot.get(k):
                slot[k] = v
        slot["keys"].add(fk)

    for f in findings:
        fk = _finding_key(f)
        host = _host_of(f)
        text = f.get("finding") or ""
        hay = (f.get("artifact") or "") + "\n" + text

        if host and host != "unknown":
            add("hosts", host, fk)

        # network — IPv4 addresses referenced by the finding, per host
        for ip in _RE_IPV4.findall(text):
            add("network", ip, fk, host=host, dedup_ci=False)

        # identities — profile paths + real-user SIDs (RID >= 1000)
        for u in _RE_USER_PATH.findall(hay):
            if u.lower() not in _NON_USERS:
                add("identities", u, fk)
        for full, rid in zip(_RE_SID_FULL.findall(text), _RE_SID_USER.findall(text)):
            if int(rid) >= 1000:
                add("identities", full, fk, dedup_ci=False)

        # files — validated process_path basename + filenames in text (per host)
        pp = f.get("process_path") or ""
        if _looks_like_path(pp):
            add("files", re.split(r'[\\/]', pp)[-1], fk, host=host)
        for fn in _RE_FILE.findall(text):
            add("files", fn, fk, host=host)

        # processes — structured field (with parent) + executable images named in
        # the finding text (per host). Parent attaches only from the structured field.
        pn = f.get("process_name")
        if pn:
            add("processes", pn, fk, host=host, parent=(f.get("parent_process") or None))
        for img in _RE_PROC.findall(text):
            add("processes", img, fk, host=host)

        # registry keys (Windows) — per host
        for rk in _RE_REG.findall(text):
            add("registry_keys", rk, fk, host=host)

        # certificates — discrete identifiers only, per host
        for tp in _RE_THUMB.findall(text):
            add("certificates", tp.lower(), fk, host=host, dedup_ci=False)
        for cn in _RE_CN.findall(text):
            add("certificates", "CN=" + cn.strip(), fk, host=host)
        for cf in _RE_CERTFILE.findall(text):
            add("certificates", cf, fk, host=host)

        # sessions — logon/session IDs, per host
        for lid in _RE_LOGON.findall(text):
            add("sessions", lid, fk, host=host)

    out = {}
    for cat, od in cats.items():
        items = []
        for slot in od.values():
            slot["keys"] = sorted(slot["keys"])
            slot["count"] = len(slot["keys"])
            items.append(slot)
        items.sort(key=lambda x: (x.get("host", ""), -x["count"], x["name"].lower()))
        out[cat] = items
    return out


def find_ground_truth_doc(case_dir: Path):
    """Return the path of an actual ground-truth DOCUMENT on disk for this dataset,
    or None. The validator's hard-coded built-in (FOR508 fallback) does NOT count —
    only a real ground_truth.json file in a conventional location does."""
    case_id = case_dir.name
    candidates = [
        case_dir / "ground_truth.json",
        case_dir / "analysis" / "ground_truth.json",
        Path("/cases/project/vigia-cases") / case_id / "ground_truth.json",
        Path("/cases/project/vigia-cases/cases") / case_id / "ground_truth.json",
    ]
    for p in candidates:
        try:
            if p.is_file():
                return str(p)
        except OSError:
            continue
    return None


def load_coverage(analysis_dir: Path):
    return _load_json(analysis_dir / "coverage_report.json") or {}


# Exec-gateway profile (forensic|dev), shared source-of-truth with
# runclawd_exec_gateway.py. Fail-closed to forensic.
GATEWAY_MODE_FILE = Path("/cases/project/.gateway_mode")


def load_mode():
    try:
        raw = GATEWAY_MODE_FILE.read_text().strip()
        m = json.loads(raw).get("mode") if raw.startswith("{") else raw
    except Exception:
        m = None
    return "dev" if m == "dev" else "forensic"


# The SIFT MCP server (sift-ir-agent) appends every tool call + underlying OS
# exec to this ledger, one JSON object per line (written by parsers/audit.py).
# The "MCP Server Activity" panel tails it. Override with SIFT_MCP_AUDIT_LOG
# or --mcp-log.
MCP_AUDIT_LOG = os.environ.get("SIFT_MCP_AUDIT_LOG",
                               "/home/la/analysis/mcp_server_audit.log")

# The server writes its tool catalogue here on startup; the panel hover lists it.
MCP_MANIFEST = Path(os.environ.get("SIFT_MCP_MANIFEST",
                                   "/home/la/analysis/mcp_manifest.json"))

# The exec gateway (runclawd_exec_gateway.py) appends every validated command,
# sanctioned commit, and mode change here. The "Agent Activity" panel tails it —
# this is the agent's shell/gateway activity, complementing MCP Server Activity.
GATEWAY_AUDIT_LOG = Path(os.environ.get("EXEC_GATEWAY_AUDIT_LOG",
                                        "/home/la/analysis/exec_gateway_audit.log"))

# Semantic agent-activity events (phases, judge decisions, enrichment) emitted by
# the agent via `guardrails.py activity`; merged into the Agent Activity feed.
AGENT_ACTIVITY_LOG = Path(os.environ.get("AGENT_ACTIVITY_LOG",
                                         "/home/la/analysis/agent_activity.log"))


def load_gateway_activity(log_path: Path, limit: int = 40):
    """Tail the exec-gateway ledger into an Agent Activity feed (newest first)."""
    empty = {"events": [], "total": 0, "allowed": 0, "denied": 0,
             "log_present": False, "last_ts": None, "seconds_since_last": None}
    try:
        if not log_path.exists():
            return empty
        text = log_path.read_text(errors="replace")
    except OSError:
        return empty
    raw = []
    for ln in text.splitlines()[-2000:]:
        ln = ln.strip()
        if not ln:
            continue
        try:
            raw.append(json.loads(ln))
        except json.JSONDecodeError:
            continue
    events = []
    allowed = denied = 0
    for e in raw:
        act = e.get("action", "?")
        dec = e.get("decision", "")
        if dec == "allow":
            allowed += 1
        elif dec == "deny":
            denied += 1
        if act in ("validate", "exec_request"):
            summary = (e.get("command", "") or "")[:120]
        elif act == "exec_complete":
            summary = f"exit {e.get('exit_code')} ({e.get('status')})"
        elif act == "commit_findings":
            summary = (f"{e.get('committed', '?')} findings → {os.path.basename(e.get('path', '') or '')}"
                       if dec == "allow" else f"denied: {e.get('reason', '')}")
        elif act == "commit_artifact":
            summary = (str(e.get("artifact", "")) if dec == "allow"
                       else f"denied: {e.get('reason', '')}")
        elif act == "set_mode":
            summary = f"mode → {e.get('mode', '')}"
        elif act == "auth_failure":
            summary = "auth failure"
        else:
            summary = e.get("reason", "") or ""
        events.append({"ts": e.get("ts"), "action": act, "decision": dec, "summary": summary})
    # Merge in semantic agent-activity events (phases, judge decisions, enrichment)
    # so the panel shows what the agent is doing, not just shell/gateway calls.
    try:
        if AGENT_ACTIVITY_LOG.exists():
            for ln in AGENT_ACTIVITY_LOG.read_text(errors="replace").splitlines()[-2000:]:
                ln = ln.strip()
                if not ln:
                    continue
                try:
                    a = json.loads(ln)
                except json.JSONDecodeError:
                    continue
                events.append({"ts": a.get("ts"), "action": a.get("event") or "activity",
                               "decision": "", "summary": a.get("detail", "")})
    except OSError:
        pass
    events.sort(key=lambda e: e.get("ts") or "", reverse=True)
    total = len(events)
    last_ts = events[0]["ts"] if events else None
    seconds_since_last = None
    if last_ts:
        try:
            dt = datetime.strptime(last_ts, "%Y-%m-%dT%H:%M:%SZ")
            seconds_since_last = max(0, int((datetime.utcnow() - dt).total_seconds()))
        except ValueError:
            pass
    events = events[:limit]
    return {"events": events, "total": total, "allowed": allowed, "denied": denied,
            "log_present": True, "last_ts": last_ts, "seconds_since_last": seconds_since_last}


def load_mcp_policy():
    """Return the MCP server's exposed tool catalogue (from its manifest).
    This replaces the old gateway-allowlist hover: the panel now reflects the
    real sift-ir-agent MCP server, not the exec-gateway."""
    m = _load_json(MCP_MANIFEST)
    if m and m.get("tools"):
        return {"reachable": True, "server": m.get("server", "sift-ir-agent"),
                "transport": m.get("transport", "stdio"), "tools": m["tools"]}
    return {"reachable": False, "server": "sift-ir-agent", "tools": []}


def load_mcp_activity(log_path: Path, limit: int = 40):
    """
    Parse the MCP server's activity ledger into a live stream:
      kind="call"   — an MCP tool function was invoked (fn + args)
      kind="exec"   — that tool ran a forensic binary (command + exit code)
      kind="result" — the tool returned (folded into its call row)

    Never raises — returns an empty/flagged payload when the log is missing
    or unreadable so the dashboard can degrade gracefully.
    """
    empty = {"events": [], "requests": 0, "allowed": 0, "denied": 0,
             "exec_count": 0, "log_present": False, "readable": False,
             "last_ts": None, "seconds_since_last": None}
    try:
        if not log_path.exists():
            return empty
    except OSError:
        return empty
    try:
        text = log_path.read_text(errors="replace")
    except (OSError, PermissionError):
        e = dict(empty)
        e["log_present"] = True
        return e

    raw = []
    for ln in text.splitlines()[-2000:]:
        ln = ln.strip()
        if not ln:
            continue
        try:
            raw.append(json.loads(ln))
        except json.JSONDecodeError:
            continue

    ERR = ("error", "missing", "timeout")
    events = []
    pending = {}            # fn -> its open 'call' event awaiting a 'result'
    calls = execs = ok = errors = 0
    for e in raw:
        kind = e.get("kind")
        fn = e.get("fn", "?")
        ts = e.get("ts")
        if kind == "call":
            calls += 1
            ev = {"ts": ts, "kind": "call", "caller": "agent", "fn": fn,
                  "command": e.get("args", ""), "decision": "allow",
                  "reason": "", "status": "running", "exit_code": None}
            events.append(ev)
            pending[fn] = ev
        elif kind == "exec":
            execs += 1
            st = e.get("status", "ok")
            if st in ERR:
                errors += 1
            else:
                ok += 1
            events.append({
                "ts": ts, "kind": "exec", "caller": "agent", "fn": fn,
                "command": e.get("command", ""), "decision": "allow",
                "reason": "", "status": st, "exit_code": e.get("exit_code"),
            })
        elif kind == "result":
            ev = pending.pop(fn, None)
            if ev is not None:                 # fold result into its call row
                ev["status"] = e.get("status", "ok")
                ev["reason"] = e.get("error") or ""

    last_ts = raw[-1].get("ts") if raw else None
    seconds_since_last = None
    if last_ts:
        try:
            dt = datetime.strptime(last_ts, "%Y-%m-%dT%H:%M:%SZ")
            seconds_since_last = max(0, int((datetime.utcnow() - dt).total_seconds()))
        except ValueError:
            seconds_since_last = None

    events = list(reversed(events))[:limit]   # newest first, capped
    return {
        "events": events,
        "requests": calls,                     # MCP tool calls
        "allowed": ok, "denied": errors,       # OS execs that succeeded / failed
        "exec_count": execs,                   # total OS execs
        "log_present": True, "readable": True,
        "last_ts": last_ts, "seconds_since_last": seconds_since_last,
    }


# ---------------------------------------------------------------------------
# Flask app factory
# ---------------------------------------------------------------------------
def create_app(case_dir: Path, mcp_log: Path = None) -> Flask:
    app = Flask(__name__)
    analysis_dir = case_dir / "analysis"
    mcp_log_path = Path(mcp_log) if mcp_log else Path(MCP_AUDIT_LOG)
    start_time = datetime.now()

    @app.route("/")
    def index():
        return render_template_string(HTML_TEMPLATE, case=str(case_dir))

    @app.route("/api/findings")
    def api_findings():
        findings = load_findings(analysis_dir)
        # Order by event timestamp, newest first; undated findings sink to the bottom.
        ordered = sorted(findings, key=lambda f: (f.get("timestamp") or ""), reverse=True)
        return jsonify({"findings": ordered, "count": len(findings)})

    @app.route("/api/entities")
    def api_entities():
        return jsonify(extract_entities(load_findings(analysis_dir)))

    @app.route("/api/theory")
    def api_theory():
        return jsonify(load_theory(analysis_dir))

    @app.route("/api/accuracy")
    def api_accuracy():
        data = load_accuracy(analysis_dir)
        doc = find_ground_truth_doc(case_dir)
        data["ground_truth_present"] = doc is not None   # a real document, not the built-in
        data["ground_truth_doc"] = doc
        return jsonify(data)

    @app.route("/api/mcp")
    def api_mcp():
        return jsonify(load_mcp_activity(mcp_log_path))

    @app.route("/api/agent-activity")
    def api_agent_activity():
        return jsonify(load_gateway_activity(GATEWAY_AUDIT_LOG))

    @app.route("/api/mcp-policy")
    def api_mcp_policy():
        return jsonify(load_mcp_policy())

    @app.route("/api/coverage")
    def api_coverage():
        return jsonify(load_coverage(analysis_dir))

    @app.route("/api/mode", methods=["GET", "POST"])
    def api_mode():
        if request.method == "POST":
            data = request.get_json(silent=True) or {}
            new = data.get("mode")
            if new not in ("dev", "forensic"):
                return jsonify({"error": "mode must be 'dev' or 'forensic'"}), 400
            GATEWAY_MODE_FILE.write_text(json.dumps({"mode": new, "set_by": "dashboard"}))
            return jsonify({"mode": new})
        return jsonify({"mode": load_mode()})

    # ── click-to-install for escalation-path tool recommendations ──
    # Only whitelisted tools (enforced again in install_tool.py) can be installed,
    # and the installer fetches ONLY the official upstream release. The install
    # runs detached as a subprocess; the UI polls /api/install-status.
    INSTALLABLE = {"Velociraptor"}
    INSTALLER   = Path("/home/la/analysis/install_tool.py")
    STATUS_FILE = Path("/home/la/analysis/install_status.json")

    @app.route("/api/install-tool", methods=["POST"])
    def api_install_tool():
        name = (request.get_json(silent=True) or {}).get("name", "")
        if name not in INSTALLABLE:
            return jsonify({"ok": False, "error": f"{name!r} is not installable"}), 400
        cur = _load_json(STATUS_FILE) or {}
        if cur.get("name") == name and cur.get("state") not in ("done", "error", None):
            return jsonify({"ok": True, "already": True, "state": cur.get("state")})
        STATUS_FILE.write_text(json.dumps(
            {"name": name, "state": "starting", "message": "Launching installer…",
             "pct": 0}, indent=2))
        subprocess.Popen([sys.executable, str(INSTALLER), name],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         start_new_session=True)
        return jsonify({"ok": True, "name": name})

    @app.route("/api/install-status")
    def api_install_status():
        return jsonify(_load_json(STATUS_FILE) or {})

    @app.route("/api/status")
    def api_status():
        findings = load_findings(analysis_dir)
        uptime = str(datetime.now() - start_time).split(".")[0]

        hit_stages = {f.get("kill_chain_stage") for f in findings
                      if f.get("kill_chain_stage")}
        kill_chain = [{"key": k, "label": lbl, "hit": k in hit_stages}
                      for k, lbl in KILL_CHAIN_ORDER]

        intents = {"MALICE": 0, "SUSPICION": 0, "NEGLIGENCE": 0}
        for f in findings:
            ic = f.get("intent_class", "")
            if ic in intents:
                intents[ic] += 1

        ai_count   = sum(1 for f in findings if f.get("ai_enriched"))
        corrections = sum(1 for f in findings if f.get("self_correction"))
        flagged    = sum(1 for f in findings if f.get("judge_review"))
        last_tool  = findings[-1].get("tool", "—") if findings else "—"
        tools      = sorted({f.get("tool") for f in findings if f.get("tool")})

        # mtime of the findings ledger — bumps on every write (append OR in-place
        # edit), so the frontend can detect enrichment/flagging/correction activity
        # that leaves findings_count unchanged.
        try:
            findings_mtime = (analysis_dir / "findings_log.json").stat().st_mtime
        except OSError:
            findings_mtime = None

        return jsonify({
            "uptime":         uptime,
            "findings_count": len(findings),
            "kill_chain":     kill_chain,
            "intents":        intents,
            "ai_count":       ai_count,
            "det_count":      len(findings) - ai_count,
            "corrections":    corrections,
            "flagged":        flagged,
            "last_tool":      last_tool,
            "tools":          tools,
            "findings_mtime": findings_mtime,
            "case":           str(case_dir),
            "as_of":          datetime.now().isoformat(),
        })

    return app


# ---------------------------------------------------------------------------
# HTML / CSS / JS — single self-contained template
# ---------------------------------------------------------------------------
HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>IR Agent Dashboard</title>
<style>
/* ── Reset & tokens ── */
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
:root {
  --bg:       #0d1117;
  --surface:  #161b22;
  --border:   #30363d;
  --text:     #e6edf3;
  --muted:    #8b949e;
  --accent:   #58a6ff;
  --hit:      #3fb950;
  --malice:   #f85149;
  --susp:     #d29922;
  --neg:      #6e7681;
  --ai:       #a371f7;
  --det:      #58a6ff;
  --warn:     #d29922;
}
html, body {
  height: 100%;
  font-family: 'Segoe UI', system-ui, sans-serif;
  background: var(--bg);
  color: var(--text);
  font-size: 14px;
}

/* ── Header ── */
header {
  background: var(--surface);
  border-bottom: 1px solid var(--border);
  padding: 10px 20px;
  display: flex; align-items: center; justify-content: space-between;
  position: sticky; top: 0; z-index: 10;
  gap: 16px;
}
.hdr-title {
  display: flex; align-items: center; gap: 8px;
  font-size: 15px; font-weight: 600; color: var(--accent);
  white-space: nowrap;
}
.pulse {
  display: inline-block; width: 8px; height: 8px;
  border-radius: 50%; background: var(--hit);
  animation: blink 1.4s ease-in-out infinite;
}
@keyframes blink { 0%,100%{opacity:1} 50%{opacity:.25} }
.hdr-case {
  font-size: 11px; color: var(--muted); font-family: monospace;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.agent-status {
  display: inline-flex; align-items: center; gap: 6px; width: fit-content;
  font-size: 10px; font-weight: 700; letter-spacing: .04em; text-transform: uppercase;
  padding: 2px 9px; border-radius: 10px; cursor: default; white-space: nowrap;
  border: 1px solid var(--border); background: var(--surface); color: var(--muted);
}
.agent-status .as-dot { width: 7px; height: 7px; border-radius: 50%; background: var(--muted); flex-shrink: 0; }
.agent-status.working      { color: var(--hit); border-color: #18391f; background: #0b2918; }
.agent-status.working .as-dot { background: var(--hit); animation: blink 1.4s ease-in-out infinite; }
.agent-status.idle         { color: var(--muted); }
.agent-status.idle .as-dot { background: var(--muted); }
.agent-status.malfunction  { color: var(--malice); border-color: #3a1414; background: #1a0808; }
.agent-status.malfunction .as-dot { background: var(--malice); animation: blink .7s ease-in-out infinite; }
.hdr-stats { display: flex; gap: 18px; flex-shrink: 0; }
.stat { text-align: center; min-width: 48px; }
.stat .val { font-size: 20px; font-weight: 700; color: var(--accent); line-height: 1.1; }
.stat .lbl { font-size: 10px; color: var(--muted); text-transform: uppercase; letter-spacing: .05em; }
.stat.malice   .val { color: var(--malice); }
.stat.suspicion .val { color: var(--susp); }
.stat.f1       .val { color: var(--hit); }
.stat.uptime   .val { font-size: 14px; font-family: monospace; }

/* ── Main grid: 2 columns (left = findings + attack chain, right = scoring) ── */
.grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 1px;
  background: var(--border);
  height: calc(100vh - 57px);
}
.panel {
  background: var(--surface);
  display: flex; flex-direction: column;
  overflow: hidden;
  min-width: 0;
}
.panel-hdr {
  padding: 8px 14px;
  background: var(--bg);
  border-bottom: 1px solid var(--border);
  font-size: 11px; font-weight: 600;
  text-transform: uppercase; letter-spacing: .07em;
  color: var(--muted);
  display: flex; align-items: center; justify-content: space-between;
  flex-shrink: 0;
}
.badge {
  background: var(--border); border-radius: 9px;
  padding: 1px 8px; font-size: 11px; color: var(--text); font-weight: 600;
}
.panel-body {
  flex: 1; overflow-y: auto; padding: 12px 14px;
}
.panel-body::-webkit-scrollbar { width: 4px; }
.panel-body::-webkit-scrollbar-thumb { background: var(--border); border-radius: 2px; }

/* ── AI provenance legend ── */
.legend {
  display: flex; gap: 14px; flex-wrap: wrap;
  padding: 5px 14px 6px;
  border-bottom: 1px solid var(--border);
  background: var(--bg);
  flex-shrink: 0;
}
.leg { display: flex; align-items: center; gap: 5px; font-size: 10px; color: var(--muted); }
.ls { display: inline-block; width: 8px; height: 8px; border-radius: 2px; flex-shrink: 0; }
.ls.ai      { background: var(--ai); }
.ls.det     { background: var(--det); }
.ls.flagged { background: var(--malice); }
.ls.corr    { background: var(--warn); }

/* ── Finding cards ── */
.card {
  display: flex; align-items: stretch;
  background: var(--bg);
  border: 1px solid var(--border);
  border-left: 3px solid var(--border);
  border-radius: 6px; margin-bottom: 8px; overflow: hidden;
}
.card-main { flex: 1; min-width: 0; padding: 10px 12px; }
.card.MALICE     { border-left-color: var(--malice); }
.card.SUSPICION  { border-left-color: var(--susp); }
.card.NEGLIGENCE { border-left-color: var(--neg); }
.card.card-new   { animation: cardIn .7s ease; }

/* ── Per-finding MITRE tactic sidecar (iteration 2) ── */
.card-tactic {
  flex-shrink: 0; width: 86px;
  display: flex; flex-direction: column;
  align-items: center; justify-content: center; gap: 3px;
  padding: 8px 6px; text-align: center;
  border-left: 3px solid var(--border);
  background: var(--surface);
}
.ct-cap {
  font-size: 8px; font-weight: 700; letter-spacing: .09em;
  color: var(--muted); text-transform: uppercase;
}
.ct-tac { font-size: 10px; font-weight: 700; line-height: 1.18; }
.ct-tech {
  font-size: 9px; font-family: monospace; color: var(--muted);
  word-break: break-all; line-height: 1.2;
}
.card-tactic.empty-tac .ct-tac { color: var(--muted); font-weight: 500; }
@keyframes cardIn {
  0%   { opacity: 0; transform: translateY(-8px); }
  55%  { box-shadow: 0 0 0 2px var(--accent); }
  100% { opacity: 1; transform: none; box-shadow: none; }
}

/* ── Evidence basis line ── */
.evidence {
  display: flex; align-items: center; gap: 7px;
  margin-top: 8px; padding: 5px 8px;
  background: #0a1626; border: 1px solid #1f3350;
  border-left: 2px solid var(--accent); border-radius: 4px;
  font-family: monospace; font-size: 11px;
}
.ev-lbl {
  font-size: 9px; font-weight: 700; letter-spacing: .06em;
  color: var(--accent); background: #0d2138;
  padding: 1px 5px; border-radius: 3px; flex-shrink: 0;
}
.ev-art { color: var(--text); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.ev-off { color: var(--susp); flex-shrink: 0; margin-left: auto; }

/* ── Process lineage line (iteration 4 / Track B) ── */
.proc-line {
  display: flex; align-items: center; gap: 7px; flex-wrap: wrap;
  margin-top: 7px; padding: 4px 8px;
  background: #161526; border: 1px solid #2c2740;
  border-left: 2px solid var(--ai); border-radius: 4px;
  font-family: monospace; font-size: 11px;
}
.proc-lbl {
  font-size: 9px; font-weight: 700; letter-spacing: .06em;
  color: var(--ai); background: #211a36; padding: 1px 5px; border-radius: 3px; flex-shrink: 0;
}
.proc-name { color: var(--text); font-weight: 700; }
.proc-path { color: var(--muted); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.proc-parent { color: var(--susp); flex-shrink: 0; margin-left: auto; }
.pill.ts-fact { background: #0b2918; color: var(--hit); }

.card-top {
  display: flex; align-items: flex-start;
  justify-content: space-between; gap: 8px; margin-bottom: 6px;
}
.card-text { font-size: 13px; font-weight: 500; line-height: 1.4; }
.tag {
  display: inline-block; padding: 2px 7px; border-radius: 4px;
  font-size: 10px; font-weight: 600; letter-spacing: .04em; flex-shrink: 0;
}
.tag.MALICE     { background: #491219; color: var(--malice); }
.tag.SUSPICION  { background: #3b2c0f; color: var(--susp); }
.tag.NEGLIGENCE { background: #1c1f23; color: var(--neg); }
.tag.UNKNOWN    { background: #1c1f23; color: var(--muted); }

.pills { display: flex; align-items: center; gap: 5px; flex-wrap: wrap; margin-top: 4px; }
.pill {
  font-size: 10px; padding: 1px 6px; border-radius: 3px;
  background: var(--border); color: var(--muted);
}
.pill.ai      { background: #2d1f47; color: var(--ai); }
.pill.det     { background: #0c2026; color: var(--det); }
.pill.hi      { background: #0b2918; color: var(--hit); }
.pill.med     { background: #3b2c0f; color: var(--susp); }
.pill.lo      { background: #2a0c09; color: var(--malice); }
.pill.flagged { background: #3b1c1c; color: var(--malice); }

.artifact {
  font-size: 10px; color: var(--muted); font-family: monospace;
  margin-top: 5px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.empty { color: var(--muted); font-style: italic; font-size: 12px; padding: 8px 0; }

/* ── Theory panel ── */
.theory-section { margin-bottom: 16px; }
.theory-section h4 {
  font-size: 10px; font-weight: 600; text-transform: uppercase;
  color: var(--muted); letter-spacing: .06em; margin-bottom: 7px;
}
.intent-badge {
  font-size: 18px; font-weight: 700; padding: 6px 14px;
  border-radius: 6px; display: inline-block; margin-bottom: 4px;
}
.intent-badge.MALICE     { background: #491219; color: var(--malice); }
.intent-badge.SUSPICION  { background: #3b2c0f; color: var(--susp); }
.intent-badge.NEGLIGENCE { background: #1c1f23; color: var(--neg); }
.intent-badge.UNKNOWN    { background: #1c1f23; color: var(--muted); }

.narrative {
  background: var(--bg); border: 1px solid var(--border);
  border-radius: 6px; padding: 12px 14px;
  font-size: 13px; line-height: 1.75; color: var(--text);
  white-space: pre-wrap; min-height: 72px;
}
.mitre-tags { display: flex; flex-wrap: wrap; gap: 5px; }
.updated { font-size: 10px; color: var(--muted); margin-top: 6px; }

/* ── Kill chain panel ── */
.kc-bar-bg  { background: var(--border); border-radius: 4px; height: 5px; margin-bottom: 4px; }
.kc-bar-fill { background: var(--hit); border-radius: 4px; height: 5px; transition: width .5s; }
.kc-pct { font-size: 11px; color: var(--muted); margin-bottom: 4px; }
.kc-note { font-size: 10px; color: var(--muted); font-style: italic; margin-bottom: 14px; }

.kc-stage {
  display: flex; align-items: center; gap: 9px;
  padding: 6px 9px; border-radius: 5px; margin-bottom: 3px;
  background: var(--bg); border: 1px solid var(--border);
}
.kc-stage.hit { background: #0b2918; border-color: var(--hit); }
.kc-dot {
  width: 9px; height: 9px; border-radius: 50%; flex-shrink: 0;
  background: var(--border); border: 1px solid var(--muted);
}
.kc-stage.hit .kc-dot { background: var(--hit); border-color: var(--hit); box-shadow: 0 0 5px var(--hit); }
.kc-lbl { font-size: 12px; color: var(--muted); }
.kc-stage.hit .kc-lbl { color: var(--text); font-weight: 500; }

/* ── Intent chips (bottom of right panel) ── */
.intent-row { display: flex; gap: 5px; margin: 12px 0; }
.ichip {
  flex: 1; text-align: center; border-radius: 5px; padding: 6px 4px;
  font-size: 10px; font-weight: 600; text-transform: uppercase; letter-spacing: .03em;
}
.ichip.MALICE     { background: #491219; color: var(--malice); }
.ichip.SUSPICION  { background: #3b2c0f; color: var(--susp); }
.ichip.NEGLIGENCE { background: #1c1f23; color: var(--neg); }
.ichip .n { display: block; font-size: 18px; font-weight: 700; line-height: 1.2; }

/* ── Section sub-headers (right panel) ── */
.sec-hdr {
  font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: .07em;
  color: var(--muted); margin: 4px 0 9px; padding-bottom: 5px;
  border-bottom: 1px solid var(--border);
}
.findings-hdr { display: flex; align-items: baseline; gap: 10px; flex-wrap: wrap; }
.find-filter { display: inline-flex; align-items: center; gap: 8px;
  text-transform: none; letter-spacing: 0; font-weight: 400; }
.find-filter .ff-all { font-size: 10px; color: var(--muted); font-style: italic; }
.find-filter .ff-tac { font-size: 11px; font-weight: 700; color: var(--accent); }
.find-filter .ff-count { font-size: 10px; color: var(--muted); }
.filter-clear { font-size: 10px; color: var(--accent); cursor: pointer;
  border: 1px solid var(--border); border-radius: 9px; padding: 1px 7px; }
.filter-clear:hover { background: #11233b; }

/* ── Entity navigator ── */
.ent-hint { font-size: 9px; font-weight: 400; color: var(--muted); text-transform: none; letter-spacing: 0; }
.entity-nav { display: flex; flex-direction: column; gap: 2px; margin-bottom: 6px; }
.ent-cat { display: flex; align-items: center; gap: 7px; padding: 4px 6px; cursor: pointer;
  border-radius: 5px; user-select: none; }
.ent-cat:hover { background: var(--surface); }
.ent-caret { font-size: 8px; color: var(--muted); transition: transform .12s; }
.ent-cat.open .ent-caret { transform: rotate(90deg); }
.ent-label { font-size: 11px; font-weight: 600; color: var(--text); }
.ent-n { margin-left: auto; font-size: 10px; color: var(--muted);
  background: var(--surface); border: 1px solid var(--border); border-radius: 9px; padding: 0 7px; }
.ent-body { padding: 2px 0 6px 16px; display: flex; flex-direction: column; gap: 2px; }
.ent-host { font-size: 9px; text-transform: uppercase; letter-spacing: .06em; color: var(--muted);
  margin: 4px 0 1px; }
.ent-none { font-size: 10px; color: var(--muted); font-style: italic; }
.ent-item { display: flex; align-items: center; gap: 7px; padding: 2px 7px; cursor: pointer;
  border-radius: 4px; border: 1px solid transparent; font-size: 11px; }
.ent-item:hover { background: var(--surface); }
.ent-item.sel { border-color: var(--accent); background: #11233b; }
.ent-name { color: var(--text); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.ent-sub { font-size: 9px; color: var(--muted); font-family: monospace; }
.ent-c { margin-left: auto; font-size: 9px; color: var(--muted); }
.ent-item.sel .ent-name { color: var(--accent); }

/* ── Detection accuracy section ── */
.accuracy-section { margin-bottom: 18px; }
.acc-headline { display: flex; gap: 6px; margin-bottom: 9px; }
.acc-stat {
  flex: 1; text-align: center; background: var(--bg);
  border: 1px solid var(--border); border-radius: 5px; padding: 7px 4px;
}
.acc-val { font-size: 19px; font-weight: 700; color: var(--hit); line-height: 1.1; }
.acc-lbl { font-size: 9px; color: var(--muted); text-transform: uppercase; letter-spacing: .04em; margin-top: 2px; }
.acc-tpfp { display: flex; gap: 5px; margin-bottom: 10px; }
.acc-chip {
  flex: 1; text-align: center; font-size: 10px; padding: 4px 0;
  border-radius: 4px; background: var(--bg); border: 1px solid var(--border);
  color: var(--muted); text-transform: uppercase; letter-spacing: .03em;
}
.acc-chip b { font-size: 15px; display: block; line-height: 1.3; }
.acc-chip.tp b { color: var(--hit); }
.acc-chip.fp b { color: var(--malice); }
.acc-chip.fn b { color: var(--susp); }
.acc-chip { cursor: pointer; }
.acc-chip:hover { background: #11233b; }
.acc-chip.sel { outline: 1px solid var(--accent); }

/* ── MCP Server Activity window (iteration 3) ── */
.mcp-section { margin: 4px 0 16px; }
.mcp-live {
  font-size: 9px; font-weight: 700; letter-spacing: .04em; text-transform: uppercase;
  padding: 1px 7px; border-radius: 9px; background: var(--border); color: var(--muted);
}
.mcp-live.live { background: #0b2918; color: var(--hit); }
.mcp-live.idle { background: #3b2c0f; color: var(--susp); }
.mcp-stats { display: flex; gap: 5px; margin-bottom: 8px; }
.mcp-stat {
  flex: 1; text-align: center; font-size: 9px; text-transform: uppercase; letter-spacing: .03em;
  color: var(--muted); background: var(--bg); border: 1px solid var(--border);
  border-radius: 4px; padding: 4px 0;
}
.mcp-stat b { display: block; font-size: 14px; line-height: 1.3; color: var(--text); }
.mcp-stat.allow b { color: var(--hit); }
.mcp-stat.deny  b { color: var(--malice); }
.mcp-stat.exec  b { color: var(--accent); }

.mcp-feed {
  max-height: 300px; overflow-y: auto;
  background: var(--bg); border: 1px solid var(--border);
  border-radius: 6px; padding: 6px;
}
.mcp-feed::-webkit-scrollbar { width: 4px; }
.mcp-feed::-webkit-scrollbar-thumb { background: var(--border); border-radius: 2px; }

.mcp-row {
  border-left: 2px solid var(--border);
  background: var(--surface); border-radius: 4px;
  padding: 5px 7px; margin-bottom: 5px;
}
.mcp-row:last-child { margin-bottom: 0; }
.mcp-row.allow { border-left-color: var(--hit); }
.mcp-row.deny  { border-left-color: var(--malice); }
.mcp-row.run   { border-left-color: var(--accent); }
.mcp-row.new   { animation: cardIn .6s ease; }
.mcp-rtop { display: flex; align-items: center; gap: 6px; margin-bottom: 3px; }
.mcp-fn { font-family: monospace; font-size: 12px; font-weight: 700; color: var(--accent); }
.mcp-act {
  font-size: 8px; font-weight: 700; letter-spacing: .05em; text-transform: uppercase;
  padding: 1px 5px; border-radius: 3px; background: var(--border); color: var(--muted);
}
.mcp-act.exec     { background: #0c2630; color: var(--accent); }
.mcp-act.validate { background: #1c1f23; color: var(--muted); }
.mcp-act.auth     { background: #491219; color: var(--malice); }
.mcp-time { margin-left: auto; font-size: 10px; color: var(--muted); font-family: monospace; }
.mcp-cmd {
  font-family: monospace; font-size: 10px; color: var(--text);
  white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
}
.mcp-os { font-size: 10px; margin-top: 3px; display: flex; align-items: center; gap: 5px; }
.mcp-os .arrow { color: var(--muted); font-family: monospace; }
.mcp-os .res { font-family: monospace; }
.mcp-os.ok  .res { color: var(--hit); }
.mcp-os.bad .res { color: var(--malice); }
.mcp-os.run .res { color: var(--susp); }
.mcp-deny-reason { font-size: 10px; color: var(--malice); margin-top: 3px; }

/* ── Status table ── */
.status-section { margin-top: 12px; }
.status-section .panel-hdr { padding: 6px 0; background: transparent; border: none; margin-bottom: 6px; }
.last-tool {
  background: var(--bg); border: 1px solid var(--border);
  border-radius: 4px; padding: 7px 10px;
  font-family: monospace; font-size: 12px; color: var(--accent);
  margin-bottom: 10px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.srow { display: flex; justify-content: space-between; padding: 3px 0; font-size: 12px; }
.srow .sk { color: var(--muted); }

/* ── Reusable hover tooltip (iteration 4) ──
   Any element with a data-tip attribute shows a dark popover on hover.
   Multi-line tips: put \n in data-tip (rendered via white-space: pre-line). */
.tip-host { position: relative; cursor: help; border-bottom: 1px dotted var(--muted); }
.tip-host::after {
  content: attr(data-tip);
  position: absolute; top: 130%; left: 0; z-index: 50;
  min-width: 180px; max-width: 320px; width: max-content;
  background: #05080d; color: var(--text);
  border: 1px solid var(--border); border-radius: 6px;
  padding: 8px 10px; font-size: 11px; font-weight: 400;
  line-height: 1.5; white-space: pre-line; text-transform: none; letter-spacing: 0;
  font-family: 'Segoe UI', system-ui, sans-serif;
  box-shadow: 0 6px 20px rgba(0,0,0,.55);
  opacity: 0; visibility: hidden; transform: translateY(-3px);
  transition: opacity .12s ease, transform .12s ease;
  pointer-events: none;
}
.tip-host:hover::after { opacity: 1; visibility: visible; transform: none; }
.tip-host.tip-right::after { left: auto; right: 0; }

/* ── AI-enrichment ratio (legend) ── */
.ai-ratio { margin-left: auto; color: var(--ai); font-weight: 600; }
.ai-ratio b { color: var(--ai); }

/* ── Card AI-analysis expander (iteration 4) ── */
.ai-toggle {
  display: inline-flex; align-items: center; gap: 4px; margin-top: 7px;
  font-size: 10px; font-weight: 600; color: var(--ai);
  background: #1b1230; border: 1px solid #2d1f47; border-radius: 4px;
  padding: 2px 7px; cursor: pointer; user-select: none;
}
.ai-toggle:hover { background: #2d1f47; }
.ai-detail {
  margin-top: 7px; padding: 9px 11px;
  background: #150e26; border: 1px solid #2d1f47;
  border-left: 2px solid var(--ai); border-radius: 5px;
  font-size: 12px; line-height: 1.6; color: var(--text);
}
.ai-detail .ai-cap {
  font-size: 9px; font-weight: 700; letter-spacing: .06em; text-transform: uppercase;
  color: var(--ai); display: block; margin-bottom: 4px;
}

/* ── MITRE tactics navigator under Case Theory (iteration 4) ── */
.tac-nav { display: flex; flex-direction: column; gap: 4px; }
.tac-item { background: var(--bg); border: 1px solid var(--border); border-radius: 5px; overflow: hidden; }
.tac-row {
  display: flex; align-items: center; gap: 8px; padding: 6px 9px;
  cursor: pointer; user-select: none;
}
.tac-row:hover { background: var(--surface); }
.tac-caret { font-size: 9px; color: var(--muted); width: 9px; flex-shrink: 0; transition: transform .15s; }
.tac-item.open .tac-caret { transform: rotate(90deg); }
.tac-dot { width: 9px; height: 9px; border-radius: 2px; flex-shrink: 0; }
.tac-name { font-size: 12px; font-weight: 600; flex: 1; }
.tac-count { font-size: 11px; font-weight: 700; color: var(--text); background: var(--border); border-radius: 9px; padding: 0 7px; }
.tac-body { display: none; padding: 2px 9px 8px 26px; }
.tac-item.open .tac-body { display: block; }
.tac-fact { font-size: 11px; line-height: 1.45; padding: 5px 0; border-top: 1px solid var(--border); }
.tac-fact:first-child { border-top: none; }
.tac-fact .tf-meta { display: block; margin-top: 2px; font-family: monospace; font-size: 10px; color: var(--muted); }
.tac-fact .tf-tech { color: var(--susp); }

/* ── Evidence Coverage (iteration 4 / Track B step 2) ── */
.coverage-section { margin: 4px 0 16px; }
.cov-flag {
  font-size: 9px; font-weight: 700; letter-spacing: .04em; text-transform: uppercase;
  padding: 1px 7px; border-radius: 9px; background: var(--border); color: var(--muted);
}
.cov-flag.ok  { background: #0b2918; color: var(--hit); }
.cov-flag.bad { background: #3b1c1c; color: var(--malice); }
.cov-gaps { display: flex; flex-wrap: wrap; gap: 5px; margin-top: 8px; }
.cov-chip {
  font-size: 10px; padding: 2px 7px; border-radius: 4px;
  background: var(--bg); border: 1px solid var(--border); color: var(--muted);
}
.cov-chip.stage   { border-color: var(--susp); color: var(--susp); }
.cov-chip.source  { border-color: var(--malice); color: var(--malice); }
.cov-chip.clean   { border-color: var(--hit); color: var(--hit); }
.cov-chip b { font-weight: 700; }
/* escalation paths — not-installed tool-of-choice once scope goes live/multi-host */
.cov-escalation { margin-top: 10px; }
.cov-esc-hdr {
  font-size: 9px; font-weight: 700; letter-spacing: .05em; text-transform: uppercase;
  color: var(--muted); margin-bottom: 5px;
}
.cov-esc-row {
  display: flex; align-items: baseline; gap: 7px; flex-wrap: wrap;
  font-size: 10px; padding: 4px 8px; margin: 4px 0; border-radius: 5px;
  background: var(--bg); border: 1px dashed var(--accent);
}
.cov-esc-name { font-weight: 700; color: var(--accent); }
.cov-esc-scope {
  font-size: 8px; font-weight: 700; letter-spacing: .04em; text-transform: uppercase;
  padding: 1px 6px; border-radius: 8px; background: #11233b; color: var(--accent);
}
.cov-esc-covers { color: var(--muted); }
.cov-esc-covers b { color: var(--text); font-weight: 600; }
.cov-esc-install {
  margin-left: auto; font-size: 10px; font-weight: 700; cursor: pointer;
  background: #11233b; color: var(--accent); border: 1px solid var(--accent);
  border-radius: 5px; padding: 3px 11px; white-space: nowrap;
}
.cov-esc-install:hover:not(:disabled) { background: var(--accent); color: #06101d; }
.cov-esc-install:disabled { opacity: .55; cursor: default; }
.cov-esc-installed { margin-left: auto; font-size: 10px; font-weight: 700; color: var(--hit); white-space: nowrap; }
.cov-esc-prog { flex-basis: 100%; font-size: 9.5px; color: var(--muted); margin-top: 4px; }
.cov-esc-prog.err { color: var(--malice); }
.cov-esc-bar { flex-basis: 100%; height: 3px; background: var(--border); border-radius: 2px; margin-top: 4px; overflow: hidden; }
.cov-esc-bar > i { display: block; height: 100%; background: var(--accent); width: 0; transition: width .35s; }
/* ── bipartite tool/data map (data → tools → kill-chain stages) ── */
.graphsvg { width: 100%; display: block; margin-top: 4px; font-family: 'Cascadia Code', monospace; }
.graphsvg text { font-size: 8.5px; fill: var(--text); pointer-events: none; }
.gcolhdr { fill: var(--muted); font-size: 8px; letter-spacing: .09em; font-weight: 700; }
.gedge { fill: none; stroke: var(--muted); stroke-width: 1.1; opacity: .5; transition: opacity .12s; }
.gedge.present { opacity: .6; }                       /* solid — points at a present block */
.gedge.missing { stroke-dasharray: 3 3; opacity: .5; }  /* dashed — points at a not-yet-present block */
.gnode rect { fill: var(--bg); stroke: var(--border); stroke-width: 1; transition: stroke-width .1s; }
.gnode text { fill: var(--muted); }
.gnode.src rect { stroke: #3a4250; } .gnode.src text { fill: var(--text); }
.gnode.art rect { fill: var(--bg); stroke: #3a4250; } .gnode.art text { fill: var(--text); }
/* simplified scheme: border colour = data source; solid = present, dashed = not.
   text follows present/missing (these win over the older status-class colours). */
.gnode.present text { fill: var(--text); }
.gnode.missing text { fill: var(--muted); font-style: italic; }
.gnode[data-install] { cursor: pointer; }
.gnode[data-install]:hover rect { fill: #11233b; }
.gnode.tool.applied rect { stroke: var(--hit); } .gnode.tool.applied text { fill: var(--hit); }
.gnode.tool.ready rect { stroke: #3a4250; } .gnode.tool.ready text { fill: var(--text); }
.gnode.tool.installable rect { stroke: var(--accent); cursor: pointer; }
.gnode.tool.installable text { fill: var(--accent); }
.gnode.tool.installable { cursor: pointer; }
.gnode.tool.installable:hover rect { fill: #11233b; }
.gnode.tool.installing rect { stroke: var(--accent); stroke-dasharray: 2 2; }
.gnode.tool.installing text { fill: var(--accent); }
.gnode.tool.done rect { stroke: var(--hit); } .gnode.tool.done text { fill: var(--hit); }
.gnode.tool.unbuilt rect { stroke: var(--border); stroke-dasharray: 2 2; }
.gnode.tool.unbuilt text { font-style: italic; fill: #6e7681; }
.gnode.tool.absent rect { stroke-dasharray: 2 2; }
.gnode.stage.hit rect { fill: #10161f; } .gnode.stage.hit text { fill: var(--text); }
.gnode.stage.gap rect { stroke-dasharray: 2 2; } .gnode.stage.gap text { fill: var(--muted); }
.gnode.stage { cursor: pointer; }
.gnode.stage.sel rect { stroke: var(--accent); stroke-width: 2.2; fill: #11233b; }
.gnode.stage.sel text { fill: var(--accent); font-weight: 700; }
.graphsvg.dimmed .gnode, .graphsvg.dimmed .gedge { opacity: .13; }
.graphsvg.dimmed .gnode.hl, .graphsvg.dimmed .gedge.hl { opacity: 1; }
.graphsvg .gnode.hl rect { stroke-width: 1.9; }
.glegend { font-size: 8.5px; color: var(--muted); margin-top: 5px; }
.glegend .gi { color: var(--accent); font-weight: 700; }
.mode-toggle { display:inline-flex; align-items:center; gap:5px; cursor:pointer;
  font-size:10px; font-weight:600; text-transform:uppercase; letter-spacing:.04em;
  padding:2px 8px; border-radius:10px; border:1px solid #30363d; width:max-content;
  margin-top:2px; user-select:none; }
.mode-toggle .mt-dot { width:7px; height:7px; border-radius:50%; }
.mode-toggle.forensic { color:#3fb950; border-color:#1c3a24; background:#0b2014; }
.mode-toggle.forensic .mt-dot { background:#3fb950; }
.mode-toggle.dev { color:#d29922; border-color:#3b2c0f; background:#241a06; }
.mode-toggle.dev .mt-dot { background:#d29922; box-shadow:0 0 5px #d29922; }
</style>
</head>
<body>

<header>
  <div style="display:flex;flex-direction:column;gap:3px;min-width:0">
    <div class="hdr-title"><span class="pulse"></span> IR Agent — Live Dashboard</div>
    <div class="hdr-case" id="h-case">{{ case }}</div>
    <div class="agent-status idle" id="agent-status" title="Agent status">
      <span class="as-dot"></span><span class="as-label">Agent status: —</span>
    </div>
    <div class="mode-toggle forensic" id="mode-toggle" data-mode="forensic"
         title="Exec-gateway profile — click to toggle. Forensic = case data MCP-only; Dev = permissive for /cases/project tooling.">
      <span class="mt-dot"></span><span class="mt-label">mode: —</span>
    </div>
  </div>
  <div class="hdr-stats">
    <div class="stat tip-host" id="tools-stat" data-tip="Tools used in this analysis."><div class="val" id="h-tools">—</div><div class="lbl">Tools</div></div>
    <div class="stat"><div class="val" id="h-total">—</div><div class="lbl">Evidence</div></div>
    <div class="stat malice"><div class="val" id="h-malice">—</div><div class="lbl">Malice</div></div>
    <div class="stat suspicion"><div class="val" id="h-suspicion">—</div><div class="lbl">Suspicion</div></div>
    <div class="stat f1 tip-host tip-right" data-tip="F1 score — the harmonic mean of precision &amp; recall: 2·P·R/(P+R). A single 0–1 detection-quality number that is high only when the agent is both accurate (few false positives) and complete (few misses). 1.0 = perfect."><div class="val" id="h-f1">—</div><div class="lbl">F1 Score</div></div>
    <div class="stat uptime"><div class="val" id="h-uptime">—</div><div class="lbl">Uptime</div></div>
  </div>
</header>

<div class="grid">

  <!-- ── Panel 1: Findings (case theory + entity navigator + findings feed) ── -->
  <div class="panel">
    <div class="panel-hdr">
      Findings
      <span class="badge" id="feed-count">0</span>
    </div>
    <div class="panel-body">

      <!-- Case theory header: overall intent + adversary narrative + active techniques -->
      <div class="theory-section">
        <h4>Overall Intent</h4>
        <div class="intent-badge UNKNOWN" id="theory-intent">UNKNOWN</div>
      </div>
      <div class="theory-section">
        <h4>Adversary Intent Narrative</h4>
        <div class="narrative" id="theory-narrative"><span class="empty">Waiting for agent analysis…</span></div>
      </div>
      <div class="updated" id="theory-updated"></div>

      <!-- Entity navigator: click an entity to filter Findings Detail below -->
      <div class="sec-hdr" style="margin-top:14px">Entities <span class="ent-hint">click to filter ›</span></div>
      <div class="entity-nav" id="entity-nav">
        <div class="empty">Waiting for agent findings…</div>
      </div>

      <!-- Findings feed sits underneath the entity navigator -->
      <div class="sec-hdr findings-hdr" style="margin-top:16px">
        <span>Findings Detail</span>
        <span class="find-filter" id="find-filter"></span>
      </div>
      <div class="legend" style="margin:0 -14px 10px">
        <span class="leg">Click a finding to expand its AI analysis ▸</span>
        <span class="leg"><span class="ls flagged"></span>Judge-flagged</span>
        <span class="leg"><span class="ls corr"></span>Self-corrected</span>
        <span class="leg ai-ratio" id="ai-ratio">AI-enriched <b>—</b> / —</span>
      </div>
      <div id="findings-body">
        <div class="empty">Waiting for agent findings…</div>
      </div>

    </div>
  </div>

  <!-- ── Panel 2: Scoring + Kill Chain + MCP activity + data↔tool map ── -->
  <div class="panel">
    <div class="panel-hdr">Scoring &amp; Kill Chain</div>
    <div class="panel-body">

      <div class="accuracy-section" id="accuracy-section">
        <div class="sec-hdr">Detection Accuracy <span id="a-vsgt" style="color:var(--muted);font-weight:400;text-transform:none;letter-spacing:0"></span></div>
        <div class="acc-headline">
          <div class="acc-stat"><div class="acc-val" id="a-f1">—</div><div class="acc-lbl">F1</div></div>
          <div class="acc-stat"><div class="acc-val" id="a-prec">—</div><div class="acc-lbl">Precision</div></div>
          <div class="acc-stat"><div class="acc-val" id="a-rec">—</div><div class="acc-lbl">Recall</div></div>
        </div>
        <div class="acc-tpfp">
          <span class="acc-chip tp" data-acc="tp" title="Click to show these findings"><b id="a-tp">—</b>True Pos</span>
          <span class="acc-chip fp" data-acc="fp" title="Click to show these findings"><b id="a-fp">—</b>False Pos</span>
          <span class="acc-chip fn" data-acc="fn" title="Click to show what was missed"><b id="a-fn">—</b>False Neg</span>
        </div>
        <div class="srow"><span class="sk tip-host" data-tip="Checks the agent's ATT&amp;CK techniques against a ground-truth answer key for this dataset. Shows coverage % (+N techniques the agent reported beyond the key · M missed). If no ground truth exists for the analysed dataset it says so instead.">Ground truth check</span><span id="a-mitre">—</span></div>
        <div class="srow"><span class="sk">Intent verdict</span><span id="a-intent">—</span></div>
        <div class="srow"><span class="sk">Stages missed</span><span id="a-missed">—</span></div>
      </div>

      <div class="sec-hdr">Kill Chain Coverage</div>
      <div class="kc-bar-bg"><div class="kc-bar-fill" id="kc-bar" style="width:0%"></div></div>
      <div class="kc-pct" id="kc-pct">0 / 12 stages</div>

      <div class="coverage-section">
        <div class="cov-escalation" id="cov-escalation"></div>
      </div>
      <div class="kc-note">Per-tactic detail now shown on each finding ›</div>

      <div class="mcp-section">
        <div class="sec-hdr"><span class="tip-host" id="mcp-policy-tip" data-tip="Hover for the MCP server tool catalogue…">MCP Server Activity</span> <span class="mcp-live" id="mcp-live">offline</span></div>
        <div class="mcp-stats">
          <span class="mcp-stat"><b id="mcp-req">0</b>calls</span>
          <span class="mcp-stat allow"><b id="mcp-allow">0</b>ok</span>
          <span class="mcp-stat deny"><b id="mcp-deny">0</b>err</span>
          <span class="mcp-stat exec"><b id="mcp-exec">0</b>OS exec</span>
        </div>
        <div class="mcp-feed" id="mcp-feed">
          <div class="empty">Waiting for MCP server activity…</div>
        </div>
      </div>

      <div class="mcp-section">
        <div class="sec-hdr"><span class="tip-host" data-tip="Exec-gateway ledger: every Bash command the agent ran (allow/deny), each sanctioned commit, and mode switches — the agent's shell/gateway activity.">Agent Activity</span> <span class="mcp-live" id="agent-live">offline</span></div>
        <div class="mcp-stats">
          <span class="mcp-stat"><b id="agent-total">0</b>actions</span>
          <span class="mcp-stat allow"><b id="agent-allow">0</b>allow</span>
          <span class="mcp-stat deny"><b id="agent-deny">0</b>deny</span>
        </div>
        <div class="mcp-feed" id="agent-feed">
          <div class="empty">Waiting for agent activity…</div>
        </div>
      </div>

      <div class="intent-row">
        <div class="ichip MALICE">   <span class="n" id="ic-malice">0</span>Malice</div>
        <div class="ichip SUSPICION"><span class="n" id="ic-susp">0</span>Suspicion</div>
        <div class="ichip NEGLIGENCE"><span class="n" id="ic-neg">0</span>Neglect</div>
      </div>

    </div>
  </div>

</div><!-- /grid -->

<script>
"use strict";
const POLL_MS = 3000;

async function get(url) {
  const r = await fetch(url);
  if (!r.ok) throw new Error(url + ' ' + r.status);
  return r.json();
}

function esc(s) {
  return String(s ?? '')
    .replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function confPill(c) {
  const m = {high:'hi', medium:'med', low:'lo'};
  return `<span class="pill ${m[c]||''}" title="Confidence / severity">conf: ${esc(c||'?')}</span>`;
}

/* ── MITRE tactic sidecar (iteration 2) ──
   kill_chain_stage maps 1:1 to an ATT&CK Enterprise tactic; each gets a scan-color.
   Canonical 14-tactic set in official order. `full` = official tactic name (used in
   the data↔tool↔stage map); `short` = compact label for tight sidecar/navigator rows. */
const TACTIC = {
  'reconnaissance':       {full:'Reconnaissance',       short:'Recon',          c:'#8b949e'},
  'resource-development': {full:'Resource Development',  short:'Resource Dev',   c:'#79c0ff'},
  'initial-access':       {full:'Initial Access',        short:'Initial Access', c:'#58a6ff'},
  'execution':            {full:'Execution',             short:'Execution',      c:'#a371f7'},
  'persistence':          {full:'Persistence',           short:'Persistence',    c:'#d29922'},
  'privilege-escalation': {full:'Privilege Escalation',  short:'Priv Esc',       c:'#db6d28'},
  'defense-evasion':      {full:'Defense Evasion',       short:'Def Evasion',    c:'#bc8cff'},
  'credential-access':    {full:'Credential Access',     short:'Cred Access',    c:'#f85149'},
  'discovery':            {full:'Discovery',             short:'Discovery',      c:'#39c5cf'},
  'lateral-movement':     {full:'Lateral Movement',      short:'Lateral Move',   c:'#e3b341'},
  'collection':           {full:'Collection',            short:'Collection',     c:'#3fb950'},
  'command-and-control':  {full:'Command and Control',   short:'C2 / C&C',       c:'#f0883e'},
  'exfiltration':         {full:'Exfiltration',          short:'Exfiltration',   c:'#ff7b72'},
  'impact':               {full:'Impact',                short:'Impact',         c:'#cf222e'},
};

function tacticBlock(f) {
  const stage = f.kill_chain_stage || '';
  const tech  = f.mitre_technique ? esc(f.mitre_technique) : '';
  const t = TACTIC[stage];
  if (!t) {
    return `<div class="card-tactic empty-tac" title="No MITRE tactic mapped">
      <div class="ct-cap">ATT&amp;CK</div>
      <div class="ct-tac">—</div>
      ${tech ? `<div class="ct-tech">${tech}</div>` : ''}
    </div>`;
  }
  return `<div class="card-tactic" title="${esc(stage)}${tech ? ' · ' + tech : ''}"
       style="border-left-color:${t.c};background:${t.c}1a">
    <div class="ct-cap">ATT&amp;CK</div>
    <div class="ct-tac" style="color:${t.c}">${esc(t.short)}</div>
    ${tech ? `<div class="ct-tech">${tech}</div>` : ''}
  </div>`;
}

/* ── Findings feed ── */
let _seen = new Set();      // finding keys already painted (for new-card highlight)
let _feedSig = '';          // signature of last render (skip re-render when unchanged)
let _allFindings = [];      // full findings list — the filtered view derives from this
let _findFilter = null;     // active filter {kind,key,label,match,stage?} | null (= show all)
let _entities = {};         // latest /api/entities payload
let _entOpen = new Set();   // expanded entity-category keys
let _entSig = '';           // skip nav re-render when unchanged

function fKey(f) { return (f.timestamp || '') + '|' + String(f.finding || '').slice(0, 48); }

let _cardOpen = new Set();   // fKeys of cards whose AI-analysis box is expanded

// Findings carry "<deterministic facts> | AI: <enrichment>"; split so the card
// face shows only the facts and the AI prose folds into a click-to-expand box.
function splitFinding(text) {
  const raw = text || '';
  const i = raw.indexOf(' | AI:');
  if (i < 0) return { facts: raw, ai: '' };
  return { facts: raw.slice(0, i).trim(), ai: raw.slice(i + 6).trim() };
}

function renderFindings(data) {
  _allFindings = data.findings || [];
  document.getElementById('feed-count').textContent = data.count;
  paintFindings();
}

// Unified Findings Detail filter — set by clicking a tactic in the map OR an
// entity in the navigator. Passing null, or the active filter again, clears it.
function setFilter(filter) {
  if (filter && _findFilter && _findFilter.key === filter.key) filter = null;   // toggle off
  _findFilter = filter || null;
  _feedSig = '';            // force a re-render through the cache guard
  paintFindings();
  markSelectedStage();
  markSelectedEntity();
}
let _acc = null;
function baseTtp(t) { return String(t || '').split('.')[0]; }
// Filters for the Detection Accuracy chips — reuse the same {kind,key,label,match} contract.
// TP/FP classify findings by their ATT&CK technique against the report's hit/extra sets;
// FN has no findings (they were missed), so it carries an items list shown by paintFindings.
function accuracyFilter(kind) {
  if (!_acc) return null;
  if (kind === 'tp') {
    const s = new Set((_acc.mitre_hit || []).map(baseTtp).filter(Boolean));
    return { kind: 'acc', key: 'acc:tp', label: 'True positives (TTP-confirmed findings)',
             match: f => { const b = baseTtp(f.mitre_technique); return !!b && s.has(b); } };
  }
  if (kind === 'fp') {
    const s = new Set((_acc.mitre_extra || []).map(baseTtp).filter(Boolean));
    return { kind: 'acc', key: 'acc:fp', label: 'False positives (TTPs outside the answer key)',
             match: f => { const b = baseTtp(f.mitre_technique); return !!b && s.has(b); } };
  }
  if (kind === 'fn') {
    const items = (_acc.fn_items && _acc.fn_items.length)
      ? _acc.fn_items : (_acc.mitre_missed || []).map(t => ({ label: t }));
    return { kind: 'fn', key: 'acc:fn', label: 'False negatives (missed by the agent)', items, match: () => false };
  }
  return null;
}
function stageFilter(stage) {
  return { kind: 'stage', key: 'stage:' + stage, stage,
           label: (TACTIC[stage] || {}).full || stage,
           match: f => (f.kill_chain_stage || '') === stage };
}
function entityFilter(cat, ent) {
  const keys = new Set(ent.keys || []);
  const cap = cat.replace(/_/g, ' ').replace(/s$/, '');
  return { kind: 'entity', key: 'ent:' + cat + ':' + (ent.host || '') + ':' + ent.name,
           label: cap + ': ' + ent.name,
           match: f => keys.has(fKey(f)) };
}

// Reflect the active filter in the "Findings Detail" header.
function updateFindingsHeader(shown, total) {
  const el = document.getElementById('find-filter');
  if (!el) return;
  if (_findFilter) {
    el.innerHTML = '<span class="ff-tac">▸ ' + esc(_findFilter.label) + '</span>'
                 + '<span class="ff-count">' + shown + ' of ' + total + '</span>'
                 + '<span class="filter-clear">show all ✕</span>';
  } else {
    el.innerHTML = '<span class="ff-all">all ' + total + ' findings · click a tactic or entity to filter</span>';
  }
}

// Highlight the selected stage node in the map (re-applied after each map render).
function markSelectedStage() {
  const svg = document.querySelector('#cov-escalation .graphsvg'); if (!svg) return;
  svg.querySelectorAll('.gnode.stage.sel').forEach(n => n.classList.remove('sel'));
  if (_findFilter && _findFilter.kind === 'stage') {
    const n = svg.querySelector('.gnode.stage[data-node="stage:' + _findFilter.stage + '"]');
    if (n) n.classList.add('sel');
  }
}

// Highlight the selected entity row in the navigator.
function markSelectedEntity() {
  document.querySelectorAll('#entity-nav .ent-item').forEach(n => {
    n.classList.toggle('sel',
      !!_findFilter && _findFilter.kind === 'entity' && n.dataset.key === _findFilter.key);
  });
}

/* ── Entity navigator (see ENTITIES.md) ── */
const ENTITY_CATS = [
  ['identities','Identities'], ['hosts','Hosts'], ['network','Network / IPs'],
  ['files','Files'], ['processes','Processes'], ['registry_keys','Registry Keys'],
  ['certificates','Certificates'], ['sessions','Sessions'],
];

function entRow(cat, it) {
  const k = 'ent:' + cat + ':' + (it.host || '') + ':' + it.name;
  const par = (cat === 'processes' && it.parent) ? `<span class="ent-sub">◂ ${esc(it.parent)}</span>` : '';
  return `<div class="ent-item" data-cat="${esc(cat)}" data-name="${esc(it.name)}" data-host="${esc(it.host || '')}" data-key="${esc(k)}" title="${esc(it.name)} — ${it.count} finding(s)">`
       + `<span class="ent-name">${esc(it.name)}</span>${par}<span class="ent-c">${it.count}</span></div>`;
}

function renderEntities(ent) {
  _entities = ent || {};
  const root = document.getElementById('entity-nav'); if (!root) return;
  const total = ENTITY_CATS.reduce((n, [k]) => n + (_entities[k] || []).length, 0);
  const sig = ENTITY_CATS.map(([k]) => k + (_entities[k] || []).length).join(',')
            + '|' + [..._entOpen].sort().join(',')
            + '|' + (_findFilter ? _findFilter.key : '');
  if (sig === _entSig) return;
  _entSig = sig;

  if (!total) { root.innerHTML = '<div class="empty">No entities in current findings.</div>'; return; }

  root.innerHTML = ENTITY_CATS.map(([cat, label]) => {
    const items = _entities[cat] || [];
    const open = _entOpen.has(cat);
    const head = `<div class="ent-cat${open ? ' open' : ''}" data-cat="${cat}">`
               + `<span class="ent-caret">▶</span><span class="ent-label">${label}</span>`
               + `<span class="ent-n">${items.length}</span></div>`;
    if (!open) return head;
    if (!items.length) return head + '<div class="ent-body"><div class="ent-none">none found</div></div>';
    let rows;
    if (items.some(it => 'host' in it)) {            // group per host
      const byHost = {};
      items.forEach(it => { (byHost[it.host || 'unknown'] = byHost[it.host || 'unknown'] || []).push(it); });
      rows = Object.keys(byHost).sort().map(h =>
        `<div class="ent-host">${esc(h)}</div>` + byHost[h].map(it => entRow(cat, it)).join('')).join('');
    } else {
      rows = items.map(it => entRow(cat, it)).join('');
    }
    return head + `<div class="ent-body">${rows}</div>`;
  }).join('');
  markSelectedEntity();
}

function onEntityNavClick(e) {
  const cat = e.target.closest('.ent-cat');
  if (cat) {
    const c = cat.dataset.cat;
    _entOpen.has(c) ? _entOpen.delete(c) : _entOpen.add(c);
    _entSig = '';                 // force re-render with new open state
    renderEntities(_entities);
    return;
  }
  const item = e.target.closest('.ent-item');
  if (item) {
    const list = _entities[item.dataset.cat] || [];
    const ent = list.find(x => (x.host || '') === item.dataset.host && x.name === item.dataset.name);
    if (ent) setFilter(entityFilter(item.dataset.cat, ent));
  }
}

// Paint the findings list honouring the active stage filter. The full list always
// lives in _allFindings; this only changes which subset is shown.
function paintFindings() {
  const body = document.getElementById('findings-body');
  const all  = _allFindings;
  if (_findFilter && _findFilter.kind === 'fn') {
    const items = _findFilter.items || [];
    updateFindingsHeader(items.length, all.length);
    body.innerHTML = items.length
      ? items.map(it => '<div style="background:var(--bg);border:1px solid var(--border);border-left:3px solid var(--susp);border-radius:6px;padding:10px 12px;margin-bottom:8px"><div style="font-size:13px;font-weight:500">⚠ Missed (in ground truth, not reported): ' + esc(it.label || it) + '</div>' + (it.reason ? '<div style="font-size:11px;color:var(--muted);margin-top:4px">' + esc(it.reason) + '</div>' : '') + '</div>').join('')
      : '<div class="empty">No false negatives — nothing missed. <span class="filter-clear">show all ✕</span></div>';
    _feedSig = '';
    return;
  }
  const list = _findFilter ? all.filter(_findFilter.match) : all;
  updateFindingsHeader(list.length, all.length);

  if (!all.length) {
    body.innerHTML = '<div class="empty">Waiting for agent findings…</div>';
    _seen.clear(); _feedSig = '';
    return;
  }
  if (!list.length) {
    body.innerHTML = '<div class="empty">No findings for <b>' + esc(_findFilter ? _findFilter.label : '') + '</b>. '
                   + '<span class="filter-clear">show all ✕</span></div>';
    _feedSig = '';
    return;
  }

  // Signature includes the filter so toggling it always re-renders.
  const sig = (_findFilter ? _findFilter.key : 'all') + '::' + list.map(fKey).join('~');
  if (sig === _feedSig) return;
  _feedSig = sig;
  const firstPaint = _seen.size === 0;   // don't animate every card on initial load

  body.innerHTML = list.map(f => {
    const key = fKey(f);
    const isNew = !firstPaint && !_seen.has(key);
    _seen.add(key);
    const intent = f.intent_class || 'UNKNOWN';
    const ts = (f.timestamp || '').replace('T',' ').substring(0,19);
    const { facts, ai } = splitFinding(f.finding);
    const flaggedPill = f.judge_review
      ? `<span class="pill flagged">⚑ flagged</span>` : '';
    const corrPill = f.self_correction
      ? `<span class="pill" style="background:#2a1f0a;color:var(--warn)">↺ corrected</span>` : '';
    const hasOff = f.offset !== null && f.offset !== undefined && f.offset !== '';
    const open = _cardOpen.has(key);
    const aiBlock = ai
      ? `<span class="ai-toggle" role="button" tabindex="0"><span class="caret">${open ? '▾' : '▸'}</span> AI analysis${f.ai_model ? ' · ' + esc(f.ai_model) : ''}</span>
    <div class="ai-detail" style="display:${open ? 'block' : 'none'}"><span class="ai-cap">AI enrichment</span>${esc(ai)}</div>`
      : '';
    return `
<div class="card ${esc(intent)}${isNew ? ' card-new' : ''}" data-fkey="${esc(key)}">
  <div class="card-main">
    <div class="card-top">
      <div class="card-text">${esc(facts || '(no description)')}</div>
      <span class="tag ${esc(intent)}">${esc(intent)}</span>
    </div>
    <div class="pills">
      ${confPill(f.confidence)}
      ${f.tool ? `<span class="pill">tool: ${esc(f.tool)}</span>` : ''}
      ${flaggedPill}${corrPill}
      ${f.event_time ? `<span class="pill ts-fact" title="Artifact event time (UTC)">timestamp: ${esc(f.event_time)}</span>` : ''}
      ${ts ? `<span class="pill">analyzed: ${esc(ts)}</span>` : ''}
    </div>
    ${f.process_name ? `<div class="proc-line" title="Process lineage">
      <span class="proc-lbl">PROC</span>
      <span class="proc-name">${esc(f.process_name)}</span>
      ${f.process_path ? `<span class="proc-path">${esc(f.process_path)}</span>` : ''}
      ${f.parent_process ? `<span class="proc-parent">◂ parent ${esc(f.parent_process)}</span>` : ''}
    </div>` : ''}
    ${f.artifact ? `<div class="evidence" title="${esc(f.artifact)}">
      <span class="ev-lbl">EVIDENCE</span>
      <span class="ev-art">${esc(String(f.artifact).split('/').pop())}</span>
      ${hasOff ? `<span class="ev-off">@ ${esc(f.offset)}</span>` : ''}
    </div>` : ''}
    ${aiBlock}
  </div>
  ${tacticBlock(f)}
</div>`;
  }).join('');
}

// Delegated handler: toggle a card's AI-analysis box (state survives polling).
function onFeedClick(e) {
  const btn = e.target.closest('.ai-toggle');
  if (!btn) return;
  const card = btn.closest('.card');
  const key = card.getAttribute('data-fkey');
  const detail = card.querySelector('.ai-detail');
  const caret = btn.querySelector('.caret');
  if (_cardOpen.has(key)) {
    _cardOpen.delete(key); detail.style.display = 'none'; caret.textContent = '▸';
  } else {
    _cardOpen.add(key); detail.style.display = 'block'; caret.textContent = '▾';
  }
}

/* ── Detection accuracy panel ── */
function pct(x) { return (x === null || x === undefined) ? '—' : (x * 100).toFixed(1) + '%'; }

function renderAccuracy(a) {
  _acc = a;
  // Ground truth check — handled first and independently of the numeric stats:
  // if there is no ground truth to score this dataset against, say so plainly.
  const gtEl = document.getElementById('a-mitre');
  const gtPresent = !!(a && a.ground_truth_present);   // requires an actual GT document on disk

  // Without a ground-truth document NOTHING in this panel can be validated, so the
  // WHOLE panel (F1 / precision / recall / TP·FP·FN / intent / stages) is blanked.
  if (!gtPresent) {
    gtEl.textContent = 'no ground truth present for this dataset';
    gtEl.style.color = 'var(--muted)'; gtEl.style.fontStyle = 'italic';
    const blank = (id, col) => { const e = document.getElementById(id);
      e.textContent = '—'; e.style.color = col || ''; };
    blank('h-f1', 'var(--muted)'); blank('a-f1', 'var(--muted)');
    blank('a-prec'); blank('a-rec');
    blank('a-tp'); blank('a-fp'); blank('a-fn');
    blank('a-intent', 'var(--muted)'); blank('a-missed', 'var(--muted)');
    document.getElementById('a-vsgt').textContent = 'no ground-truth document';
    return;
  }

  gtEl.style.color = ''; gtEl.style.fontStyle = '';
  gtEl.textContent = (a.mitre_coverage_pct != null ? a.mitre_coverage_pct.toFixed(0) + '%' : '—')
    + (a.mitre_extra?.length ? ` (+${a.mitre_extra.length} extra)` : '')
    + (a.mitre_missed?.length ? ` · ${a.mitre_missed.length} missed` : '');

  if (!a || a.f1_score === null || a.f1_score === undefined) return;
  const f1 = pct(a.f1_score);
  const q = a.f1_score >= 0.9 ? 'var(--hit)' : a.f1_score >= 0.75 ? 'var(--susp)' : 'var(--malice)';

  const hF1 = document.getElementById('h-f1');
  const aF1 = document.getElementById('a-f1');
  hF1.textContent = f1; hF1.style.color = q;
  aF1.textContent = f1; aF1.style.color = q;

  document.getElementById('a-prec').textContent = pct(a.precision);
  document.getElementById('a-rec').textContent  = pct(a.recall);
  document.getElementById('a-tp').textContent = a.true_positives  ?? '—';
  document.getElementById('a-fp').textContent = a.false_positives ?? '—';
  document.getElementById('a-fn').textContent = a.false_negatives ?? '—';

  document.getElementById('a-vsgt').textContent =
    (a.total_agent_findings != null && a.total_gt_findings != null)
      ? `${a.total_agent_findings} agent vs ${a.total_gt_findings} ground-truth` : '';

  const ic = document.getElementById('a-intent');
  ic.textContent = a.overall_intent_correct
    ? `✓ ${a.overall_intent_predicted || ''}`
    : `✗ ${a.overall_intent_predicted || '?'} vs ${a.overall_intent_gt || '?'}`;
  ic.style.color = a.overall_intent_correct ? 'var(--hit)' : 'var(--malice)';

  const missed = a.kill_chain_stages_missed || [];
  const mEl = document.getElementById('a-missed');
  mEl.textContent = missed.length ? missed.join(', ') : 'none';
  mEl.style.color = missed.length ? 'var(--susp)' : 'var(--hit)';
}

/* ── Evidence Coverage panel (iteration 4 / Track B step 2) ──
   Surfaces the gap-check: artifact classes present but routed to no analyzer,
   and kill-chain stages the available evidence could support but that have no
   finding yet. */
function renderCoverage(c) {
  if (!c || !c.summary) {
    document.getElementById('cov-escalation').innerHTML = '';
    return;
  }
  // Dynamic tool↔data↔stage map, built live from this coverage report.
  lastCoverage = c;
  renderToolGraph();
}

/* Bipartite map: data sources → tools → kill-chain stages, derived each refresh
   from the playbook + present evidence. Solid edge = tool applied (produced
   findings); dashed = recommended capability not yet used. A not-installed but
   installable tool (＋) is clickable to install. installState overrides the
   static installed flag so live progress survives the 3s refresh. */
let lastCoverage = null;
let installState = {};   // name -> {state, message, pct, version, sha256}
const INSTALLABLE = new Set(['Velociraptor']);
const STAGE_ORDER = Object.keys(TACTIC);

function renderToolGraph() {
  const el = document.getElementById('cov-escalation');
  if (!el) return;
  const c = lastCoverage;
  const classes = ((c && c.artifact_classes) ? c.artifact_classes : []).filter(x => x.present);
  if (!classes.length) { el.innerHTML = ''; return; }

  // Four columns: DATA (original acquired evidence) → ARTIFACTS (derived precooked
  // products extracted from it) → TOOLS → STAGES. Splitting the old source column
  // into DATA + ARTIFACTS is what the Evidence Coverage panel used to spell out in
  // text ("original sources" vs "derived artifacts").
  const isAcq = cl => (cl.origin || (cl.is_source ? 'acquired' : 'derived')) === 'acquired';
  const acquired = classes.filter(isAcq);
  const derived  = classes.filter(cl => !isAcq(cl));
  // node a class's tools hang off: acquired → its DATA node; derived → its ARTIFACT node
  const ownNode = cl => (isAcq(cl) ? 'src:' : 'art:') + cl.id;

  // Each DATA source gets its own line colour so its path through the map is
  // traceable. Palette scales to any number of sources (future datasets); past
  // the curated list it falls back to evenly-spread generated hues. Colour now
  // means "which data source"; solid vs dashed still means consumed vs recommended.
  const SRC_PALETTE = ['#58a6ff', '#3fb950', '#d29922', '#a371f7', '#39c5cf',
                       '#f0883e', '#ff7b72', '#e3b341', '#db6d28', '#bc8cff'];
  const NEUTRAL = '#8b949e';
  const srcColorOf = i => SRC_PALETTE[i] || `hsl(${(i * 47) % 360}, 70%, 62%)`;
  const srcColor = {};
  acquired.forEach((cl, i) => { srcColor[cl.id] = srcColorOf(i); });

  // dedup tools across all sources; union covered stages
  const tmap = new Map();
  classes.forEach(cl => (cl.tools || []).forEach(t => {
    const built = !/NOT YET BUILT/i.test(t.name);
    let tt = tmap.get(t.name);
    if (!tt) { tt = {name: t.name, installed: !!t.installed, applied: false, built,
                     covers: new Set(), role: t.role, scope: t.scope, note: t.note || ''};
               tmap.set(t.name, tt); }
    tt.applied  = tt.applied  || !!t.applied;
    tt.installed = tt.installed || !!t.installed;
    (t.covers || []).forEach(s => tt.covers.add(s));
  }));
  const tools = [...tmap.values()];
  tools.forEach(t => { const st = installState[t.name];
    if (st && st.state === 'done') t.installed = true; });

  const hitStages = new Set(((c && c.stages) || []).filter(s => s.hit).map(s => s.stage));
  // Show the FULL kill chain (all 12 ATT&CK tactics) for completeness — tactics
  // that no present tool/evidence covers still appear (dashed) instead of being
  // silently dropped from the column.
  const stages = STAGE_ORDER.slice();
  const stageMeta = {};   // stage -> coverage-report entry {hit, supportable, potential_strength, …}
  ((c && c.stages) || []).forEach(s => { stageMeta[s.stage] = s; });

  // Which DATA source feeds each tool → gives the tool (and its edges) a colour.
  // Fed by exactly one source → that source's colour; mixed/none → neutral.
  const toolSrcSet = {};
  classes.forEach(cl => { const sid = isAcq(cl) ? cl.id : cl.derives_from;
    (cl.tools || []).forEach(t => { (toolSrcSet[t.name] = toolSrcSet[t.name] || new Set()).add(sid); }); });
  const toolColor = name => { const s = toolSrcSet[name];
    return (s && s.size === 1) ? (srcColor[[...s][0]] || NEUTRAL) : NEUTRAL; };
  // "present" = installed & usable now (or applied / just-installed). Drives BOTH
  // the block's solid/dashed AND the solidity of the line pointing at it.
  const toolPresent = {};
  tools.forEach(t => { const st = installState[t.name];
    toolPresent[t.name] = !!(t.applied || (t.installed && t.built) || (st && st.state === 'done')); });

  // layout — four columns spread across the full panel width (measured live).
  // Each column's block is vertically CENTRED (not top-anchored) so unequal
  // column lengths stay visually balanced.
  const NH = 20, VG = 8, TOP = 24, SIDE = 4, NCOL = 4;
  const W = Math.max(360, Math.round(el.clientWidth || 360));
  const usable = W - SIDE * 2;
  const COLW = Math.round(usable * 0.215);
  const GAP  = Math.round((usable - COLW * NCOL) / (NCOL - 1));
  const colX = [0, 1, 2, 3].map(i => SIDE + i * (COLW + GAP));
  const cols = [
    {x: colX[0], w: COLW, kind: 'src',   items: acquired.map(cl => ({id: 'src:' + cl.id, label: cl.label, color: srcColor[cl.id]}))},
    {x: colX[1], w: COLW, kind: 'art',   items: derived.map(cl => ({id: 'art:' + cl.id, label: cl.label, routed: !!cl.routed, color: srcColor[cl.derives_from] || NEUTRAL, opts: (cl.tools || []).map(t => t.name)}))},
    {x: colX[2], w: COLW, kind: 'tool',  items: tools.map(t => ({id: 'tool:' + t.name, label: t.name, t, color: toolColor(t.name)}))},
    {x: colX[3], w: COLW, kind: 'stage', items: stages.map(s => ({id: 'stage:' + s, label: (TACTIC[s] || {}).full || s, stage: s}))},
  ];
  const blockH = n => (n > 0 ? n * NH + (n - 1) * VG : 0);
  const maxBlockH = Math.max(NH, ...cols.map(col => blockH(col.items.length)));
  const pos = {};
  cols.forEach(col => {
    const y0 = TOP + (maxBlockH - blockH(col.items.length)) / 2;   // centre this column
    col.items.forEach((n, i) => {
      n.cx = col.x; n.w = col.w; n.y = y0 + i * (NH + VG);
      pos[n.id] = {x: col.x, y: n.y, w: col.w};
    });
  });
  const H = TOP + maxBlockH + 6;

  // Lines are aligned to the BLOCKS: a line is solid when the block it points at
  // is PRESENT, dashed when it is not yet present. A tool that produced no
  // findings draws NO line onward to the kill-chain stages.
  const edges = [];
  derived.forEach(cl => {                                  // DATA → ARTIFACT
    const sid = cl.derives_from;
    const a = 'src:' + sid, b = 'art:' + cl.id;
    if (pos[a] && pos[b]) edges.push({a, b, present: !!cl.routed, color: srcColor[sid] || NEUTRAL});
  });
  classes.forEach(cl => (cl.tools || []).forEach(t => {    // (DATA|ARTIFACT) → TOOL
    const sid = isAcq(cl) ? cl.id : cl.derives_from;
    const a = ownNode(cl), b = 'tool:' + t.name;
    if (pos[a] && pos[b]) edges.push({a, b, present: !!toolPresent[t.name], color: srcColor[sid] || NEUTRAL});
  }));
  tools.forEach(t => { if (!t.applied) return;             // produced no findings → no stage line
    t.covers.forEach(s => {                                // TOOL → STAGE (evidenced stages only)
      if (!hitStages.has(s)) return;
      const a = 'tool:' + t.name, b = 'stage:' + s;
      if (pos[a] && pos[b]) edges.push({a, b, present: true, color: toolColor(t.name)});
    });
  });
  const edgeSVG = edges.map(e => {
    const A = pos[e.a], B = pos[e.b];
    const x1 = A.x + A.w, y1 = A.y + NH / 2, x2 = B.x, y2 = B.y + NH / 2, mx = (x1 + x2) / 2;
    return `<path class="gedge ${e.present ? 'present' : 'missing'}" data-a="${esc(e.a)}" data-b="${esc(e.b)}" `
         + `style="stroke:${e.color || NEUTRAL}" `
         + `d="M${x1.toFixed(1)},${y1.toFixed(1)} C${mx.toFixed(1)},${y1.toFixed(1)} ${mx.toFixed(1)},${y2.toFixed(1)} ${x2.toFixed(1)},${y2.toFixed(1)}"/>`;
  }).join('');

  // Two encodings only: BORDER COLOUR = the data source this block traces to;
  // SOLID = present, DASHED = not yet present (hover a dashed block for options).
  function nodeSVG(n, kind) {
    const maxChars = Math.max(10, Math.floor((n.w - 14) / 5.1));
    const trunc = n.label.length > maxChars ? n.label.slice(0, maxChars - 1) + '…' : n.label;
    const color = n.color || NEUTRAL;
    let cls = 'gnode ' + kind, attr = '', pre = '', tip = n.label, present = true;

    if (kind === 'tool') {
      const t = n.t, st = installState[t.name];
      const installing = st && st.state && st.state !== 'done' && st.state !== 'error';
      present = !!toolPresent[t.name];
      if (present) {
        tip = t.name + (t.applied ? ' — present, applied (produced findings)'
                                  : ' — present (installed); produced no findings here, so no line to a stage')
            + (t.note ? ' · ' + t.note : '');
      } else if (installing) {
        tip = t.name + ' — installing…';
      } else if (INSTALLABLE.has(t.name)) {
        attr = `data-install="${esc(t.name)}"`; pre = '＋ ';
        tip = t.name + ' — NOT installed. Option: click ＋ to install the official release (~/.local/bin, no sudo).'
            + (t.note ? ' · ' + t.note : '');
      } else if (!t.built) {
        tip = t.name + ' — NOT yet present. Option: build this parser.' + (t.note ? ' · ' + t.note : '');
      } else {
        tip = t.name + ' — NOT installed on this SIFT instance.' + (t.note ? ' · ' + t.note : '');
      }
    } else if (kind === 'art') {
      present = !!n.routed;
      tip = present ? n.label + ' — present, analysed'
          : n.label + ' — present, not analysed yet. Option' + ((n.opts || []).length === 1 ? '' : 's')
            + ': ' + ((n.opts || []).join(', ') || 'no tool mapped');
    } else if (kind === 'stage') {
      present = hitStages.has(n.stage);
      const sm = stageMeta[n.stage] || {}, short = (TACTIC[n.stage] || {}).full || n.stage;
      tip = present ? short + ' — evidenced'
          : sm.supportable
            ? short + ' — not yet evidenced (gap; present evidence could support it'
              + (sm.potential_strength ? ', ' + sm.potential_strength + ' strength)' : ')')
            : short + ' — not evidenced; no source in this case supports it';
    } else {   // src — original acquired evidence, always present
      tip = n.label + ' — original data source';
    }
    cls += present ? ' present' : ' missing';

    // left colour bar: DATA = its source colour, STAGE = its tactic colour
    const barColor = kind === 'stage' ? ((TACTIC[n.stage] || {}).c || NEUTRAL)
                   : kind === 'src'   ? color : '';
    const bar = barColor ? `<rect x="${n.cx}" y="${n.y}" width="3" height="${NH}" fill="${barColor}" rx="1"/>` : '';
    const tx = (kind === 'stage' || kind === 'src') ? 9 : 7;
    const dash = present ? '' : ';stroke-dasharray:3 3';
    return `<g class="${cls}" data-node="${esc(n.id)}" ${attr}><title>${esc(tip)}</title>`
         + `<rect x="${n.cx}" y="${n.y}" width="${n.w}" height="${NH}" rx="4" style="stroke:${color}${dash}"/>` + bar
         + `<text x="${n.cx + tx}" y="${n.y + NH / 2 + 3.5}">${esc(pre + trunc)}</text></g>`;
  }
  const nodesSVG = cols.map(col => col.items.map(n => nodeSVG(n, col.kind)).join('')).join('');
  const headers = ['DATA', 'ARTIFACTS', 'TOOLS', 'STAGES']
    .map((h, i) => `<text class="gcolhdr" x="${colX[i] + 2}" y="12">${h}</text>`).join('');

  // install caption (progress / result)
  let cap = '';
  const active  = Object.values(installState).find(s => s.state && s.state !== 'done' && s.state !== 'error');
  const errOne  = Object.values(installState).find(s => s.state === 'error');
  const doneOne = Object.values(installState).find(s => s.state === 'done');
  if (active) {
    cap = `<div class="cov-esc-prog">${esc(active.message || active.state)}</div>`
        + `<div class="cov-esc-bar"><i style="width:${active.pct || 0}%"></i></div>`;
  } else if (errOne) {
    cap = `<div class="cov-esc-prog err">✗ ${esc(errOne.message || 'install failed')}</div>`;
  } else if (doneOne) {
    cap = `<div class="cov-esc-prog">✓ ${esc(doneOne.name)} ${esc(doneOne.version || '')} installed · sha256 ${esc((doneOne.sha256 || '').slice(0, 12))}…</div>`;
  }

  el.innerHTML =
    '<div class="cov-esc-hdr tip-host" data-tip="Live map from the playbook + this case evidence. '
    + 'Columns: original data sources → derived artifacts → tools → kill-chain stages. '
    + 'Each block is coloured by the data source it traces to; solid = present, dashed = not yet present. '
    + 'Lines follow the blocks (solid → present, dashed → not); a tool that produced no findings has no line onward to a stage. '
    + 'Hover a dashed block for the option(s) to add it; click a ＋ tool to install (official release, ~/.local/bin, no sudo).">'
    + 'Data ↔ artifact ↔ tool map ⓘ</div>'
    + `<svg class="graphsvg" viewBox="0 0 ${W} ${H}" width="100%" height="${H}">${headers}${edgeSVG}${nodesSVG}</svg>`
    + '<div class="glegend">colour = data source&nbsp;&nbsp;▬ solid = present&nbsp;&nbsp;╌ dashed = not yet present (hover for options)&nbsp;&nbsp;<span class="gi">＋</span> install</div>'
    + cap;
  markSelectedStage();   // re-apply the selected-tactic highlight after re-render
}

function graphHover(id) {
  const svg = document.querySelector('#cov-escalation .graphsvg'); if (!svg) return;
  svg.classList.add('dimmed');
  // Edges run a -> b (data -> artifact -> tool -> stage). Highlight the full
  // lineage of the hovered node: its descendants (downstream toward stages) AND
  // its ancestors (upstream back to the dataset) — but NOT sibling branches that
  // merely share a stage/dataset hub. So we walk DIRECTED reachability both ways.
  const edges = Array.from(svg.querySelectorAll('.gedge'));
  const fwd = new Map(), bwd = new Map();
  edges.forEach(e => {
    const a = e.dataset.a, b = e.dataset.b;
    if (!fwd.has(a)) fwd.set(a, []); fwd.get(a).push(b);
    if (!bwd.has(b)) bwd.set(b, []); bwd.get(b).push(a);
  });
  const walk = (start, graph) => {
    const seen = new Set([start]), q = [start];
    while (q.length) {
      const cur = q.shift();
      (graph.get(cur) || []).forEach(n => { if (!seen.has(n)) { seen.add(n); q.push(n); } });
    }
    return seen;
  };
  const down = walk(id, fwd);   // descendants — toward the kill-chain stages
  const up   = walk(id, bwd);   // ancestors — back to the source dataset
  const nodes = new Set([...down, ...up]);
  edges.forEach(e => {
    const a = e.dataset.a, b = e.dataset.b;
    if ((down.has(a) && down.has(b)) || (up.has(a) && up.has(b))) e.classList.add('hl');
  });
  svg.querySelectorAll('.gnode').forEach(n => { if (nodes.has(n.dataset.node)) n.classList.add('hl'); });
}
function graphClear() {
  const svg = document.querySelector('#cov-escalation .graphsvg'); if (!svg) return;
  svg.classList.remove('dimmed');
  svg.querySelectorAll('.hl').forEach(x => x.classList.remove('hl'));
}

let _installPoll = null;
async function pollInstall(name) {
  try {
    const st = await get('/api/install-status');
    if (st && st.name === name) {
      installState[name] = st;
      renderToolGraph();
      if (st.state === 'done' || st.state === 'error') {
        clearInterval(_installPoll); _installPoll = null;
        if (st.state === 'done') { try { renderCoverage(await get('/api/coverage')); } catch (e) {} }
        return;
      }
    }
  } catch (e) {}
}

async function startInstall(name) {
  if (!INSTALLABLE.has(name)) return;
  const cur = installState[name];
  if (cur && cur.state && cur.state !== 'done' && cur.state !== 'error') return;  // already running
  installState[name] = {name, state: 'starting', message: 'Launching installer…', pct: 0};
  renderToolGraph();
  try {
    await fetch('/api/install-tool', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({name})
    });
  } catch (e) {
    installState[name] = {name, state: 'error', message: 'request failed'};
    renderToolGraph(); return;
  }
  if (_installPoll) clearInterval(_installPoll);
  _installPoll = setInterval(() => pollInstall(name), 1200);
  pollInstall(name);
}

/* ── MCP Server Activity panel (iteration 3) ──
   Visualises the exec-gateway ledger: each function the MCP server was asked
   to run and what it then asked the OS to do. */
let _mcpSig = '';
let _mcpSeen = new Set();
function mcpKey(e) {
  return (e.ts||'') + '|' + (e.fn||'') + '|' +
         String(e.command||'').slice(0,40) + '|' + (e.status||'');
}

function renderAgentActivity(a) {
  document.getElementById('agent-total').textContent = a.total   ?? 0;
  document.getElementById('agent-allow').textContent = a.allowed ?? 0;
  document.getElementById('agent-deny').textContent  = a.denied  ?? 0;
  const live = document.getElementById('agent-live');
  if (!a.log_present) { live.textContent = 'offline'; live.className = 'mcp-live'; }
  else if (a.seconds_since_last !== null && a.seconds_since_last <= 90) { live.textContent = '● live'; live.className = 'mcp-live live'; }
  else { live.textContent = 'idle'; live.className = 'mcp-live idle'; }
  const feed = document.getElementById('agent-feed');
  if (!a.events?.length) { feed.innerHTML = '<div class="empty">Waiting for agent activity…</div>'; return; }
  feed.innerHTML = a.events.map(e => {
    const t = (e.ts || '').substring(11, 19);
    const col = e.decision === 'deny' ? 'var(--malice,#f85149)' : 'var(--muted,#8b949e)';
    return `<div style="padding:3px 0;border-bottom:1px solid var(--border,#30363d);font-size:11px;display:flex;gap:6px;align-items:baseline">`
      + `<span style="color:var(--muted,#8b949e);font-family:monospace">${esc(t)}</span>`
      + `<span style="color:${col};font-weight:600;text-transform:uppercase;font-size:9px;white-space:nowrap">${esc(e.action)}</span>`
      + `<span style="color:var(--text,#e6edf3);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1">${esc(e.summary)}</span>`
      + `</div>`;
  }).join('');
}

function renderMcp(m) {
  document.getElementById('mcp-req').textContent   = m.requests   ?? 0;
  document.getElementById('mcp-allow').textContent = m.allowed    ?? 0;
  document.getElementById('mcp-deny').textContent  = m.denied     ?? 0;
  document.getElementById('mcp-exec').textContent  = m.exec_count ?? 0;

  const live = document.getElementById('mcp-live');
  if (!m.log_present) {
    live.textContent = 'offline'; live.className = 'mcp-live';
  } else if (m.readable === false) {
    live.textContent = 'no access'; live.className = 'mcp-live idle';
  } else if (m.seconds_since_last !== null && m.seconds_since_last <= 15) {
    live.textContent = '● live'; live.className = 'mcp-live live';
  } else {
    live.textContent = 'idle'; live.className = 'mcp-live idle';
  }

  const feed = document.getElementById('mcp-feed');
  if (!m.events?.length) {
    feed.innerHTML = '<div class="empty">' + (
      m.log_present === false ? 'No MCP activity yet — sift-ir-agent runs on demand (restart Claude Code to load it).'
      : m.readable === false  ? 'Activity ledger present but not readable by the dashboard.'
      : 'Waiting for MCP server activity…'
    ) + '</div>';
    _mcpSig = ''; _mcpSeen.clear();
    return;
  }

  const ERR = e => e.status === 'error' || e.status === 'missing' || e.status === 'timeout';
  const sig = m.events.map(mcpKey).join('~');
  if (sig === _mcpSig) return;       // nothing changed — skip re-render/flicker
  _mcpSig = sig;
  const firstPaint = _mcpSeen.size === 0;

  feed.innerHTML = m.events.map(e => {
    const key = mcpKey(e);
    const isNew = !firstPaint && !_mcpSeen.has(key);
    _mcpSeen.add(key);

    const cls = ERR(e) ? 'deny' : e.status === 'running' ? 'run' : 'allow';
    const t = (e.ts || '').substring(11, 19);
    const actCls = e.kind === 'exec' ? 'exec' : 'validate';
    const actLbl = e.kind === 'exec' ? 'EXEC→OS' : 'MCP CALL';

    let osline = '';
    if (e.kind === 'exec') {
      const ok = (e.exit_code === 0 && e.status === 'ok');
      const code = (e.exit_code !== null && e.exit_code !== undefined)
        ? ` · exit ${esc(e.exit_code)}` : '';
      osline = `<div class="mcp-os ${ok ? 'ok' : 'bad'}"><span class="arrow">→ OS</span>`
             + `<span class="res">${esc(e.status||'?')}${code}</span></div>`;
    }
    const errline = (e.kind === 'call' && ERR(e) && e.reason)
      ? `<div class="mcp-deny-reason">✗ ${esc(e.reason)}</div>` : '';

    return `
<div class="mcp-row ${cls}${isNew ? ' new' : ''}">
  <div class="mcp-rtop">
    <span class="mcp-fn">${esc(e.fn || '?')}</span>
    <span class="mcp-act ${actCls}">${actLbl}</span>
    <span class="mcp-time">${esc(t)}</span>
  </div>
  ${e.command ? `<div class="mcp-cmd" title="${esc(e.command)}">${esc(e.command)}</div>` : ''}
  ${osline}${errline}
</div>`;
  }).join('');
}

/* ── Case theory panel ── */
function renderTheory(t) {
  const intent = t.overall_intent || 'UNKNOWN';
  const el = document.getElementById('theory-intent');
  el.textContent = intent;
  el.className = 'intent-badge ' + intent;

  const narEl = document.getElementById('theory-narrative');
  if (t.narrative) {
    narEl.textContent = t.narrative;
  } else {
    narEl.innerHTML = '<span class="empty">Waiting for agent analysis…</span>';
  }

  if (t.updated_at) {
    document.getElementById('theory-updated').textContent =
      'Updated: ' + t.updated_at.replace('T',' ').substring(0,19);
  }
}

/* ── Agent status: Working / Idle / Malfunction ──
   Working      = agent actively producing (live MCP activity, a call in progress,
                  or findings updated in the last 20s).
   Idle         = backend reachable but no recent agent activity.
   Malfunction  = something is off (dashboard can't reach the backend, or the MCP
                  activity ledger is present but unreadable). */
let _prevFindings = null, _lastChangeAt = 0;
const AS_LABEL = {working: 'Working', idle: 'Idle', malfunction: 'Malfunction'};

function setAgentStatus(state, info) {
  const el = document.getElementById('agent-status');
  if (!el) return;
  el.className = 'agent-status ' + state;
  el.querySelector('.as-label').textContent = 'Agent status: ' + (AS_LABEL[state] || '—');
  if (info && info.status) {
    const s = info.status;
    el.title = [
      'Agent status: ' + (AS_LABEL[state] || '—') + (info.why ? ' — ' + info.why : ''),
      'Last tool: ' + (s.last_tool || '—'),
      'Findings: ' + (s.findings_count ?? 0) + ' (AI-enriched ' + (s.ai_count ?? 0) + ')',
      'Judge-flagged: ' + (s.flagged ?? 0),
      'Self-corrections: ' + (s.corrections ?? 0),
      'Uptime: ' + (s.uptime || '—'),
    ].join('\n');
  } else if (info && info.error) {
    el.title = 'Agent status: Malfunction — ' + info.error;
  }
}

function updateAgentStatus(s, m) {
  const now = Date.now();
  if (_prevFindings === null) { _prevFindings = s.findings_count; }
  else if (s.findings_count !== _prevFindings) { _lastChangeAt = now; _prevFindings = s.findings_count; }

  const ev = m.events || [];
  const mcpRunning = ev.some(e => e.status === 'running');
  // 90s window: during the read/analysis phase the only liveness signal is MCP
  // calls, and the agent pauses between tool bursts to reason — a short window
  // would flip to Idle mid-analysis. 90s spans normal reasoning gaps.
  const mcpRecent  = m.log_present && m.readable !== false &&
                     m.seconds_since_last !== null && m.seconds_since_last <= 90;
  const mcpUnreadable = m.log_present && m.readable === false;
  // Findings activity = findings_log.json was written recently. Keying off the file
  // mtime (not just findings_count) catches in-place updates — AI enrichment,
  // judge-flagging, self-correction — which mutate a finding without changing the count.
  const mtimeAge = (s.findings_mtime != null) ? (now / 1000 - s.findings_mtime) : Infinity;
  const findingsFresh = (mtimeAge < 25) ||
                        (_lastChangeAt && (now - _lastChangeAt) < 20000);

  let state, why;
  if (mcpUnreadable)      { state = 'malfunction'; why = 'MCP activity ledger present but unreadable'; }
  else if (mcpRunning)    { state = 'working';     why = 'MCP tool call in progress'; }
  else if (mcpRecent)     { state = 'working';     why = 'recent MCP activity'; }
  else if (findingsFresh) { state = 'working';     why = 'findings updating'; }
  else                    { state = 'idle';        why = 'no recent agent activity'; }

  setAgentStatus(state, {status: s, why});
}

/* ── Kill chain + status ── */
function renderStatus(s) {
  document.getElementById('h-total').textContent     = s.findings_count;
  document.getElementById('h-malice').textContent    = s.intents.MALICE    ?? 0;
  document.getElementById('h-suspicion').textContent = s.intents.SUSPICION ?? 0;
  document.getElementById('h-uptime').textContent    = s.uptime;

  document.getElementById('ic-malice').textContent = s.intents.MALICE    ?? 0;
  document.getElementById('ic-susp').textContent   = s.intents.SUSPICION ?? 0;
  document.getElementById('ic-neg').textContent    = s.intents.NEGLIGENCE ?? 0;

  // #tools header stat + hover list of which tools were used
  const tools = s.tools || [];
  document.getElementById('h-tools').textContent = tools.length;
  document.getElementById('tools-stat').setAttribute('data-tip',
    tools.length ? `${tools.length} tools used in this analysis:\n• ${tools.join('\n• ')}`
                 : 'No tools recorded yet.');

  // AI-enrichment as an aggregate ratio (replaces the per-card binary pill)
  const nFindings = s.findings_count || 0;
  const aiR = `<b>${s.ai_count}</b> / ${nFindings}`;
  document.getElementById('ai-ratio').innerHTML = 'AI-enriched ' + aiR;

  // Kill chain bar
  const hit = s.kill_chain.filter(k => k.hit).length;
  const total = s.kill_chain.length;
  document.getElementById('kc-bar').style.width = (hit / total * 100).toFixed(1) + '%';
  document.getElementById('kc-pct').textContent = `${hit} / ${total} stages`;
}

/* ── MCP tool-catalogue hover — read from the server's manifest ── */
async function loadPolicy() {
  const tip = document.getElementById('mcp-policy-tip');
  try {
    const p = await get('/api/mcp-policy');
    if (p.reachable && p.tools && p.tools.length) {
      const lines = p.tools.map(t => `• ${t.name}${t.desc ? ' — ' + t.desc : ''}`).join('\n');
      tip.setAttribute('data-tip',
        `MCP server "${p.server || 'sift-ir-agent'}" (${p.transport || 'stdio'}) — exposes these `
        + `${p.tools.length} typed forensic functions. Each returns structured JSON, saves raw `
        + `output for the audit trail, and is logged to the activity ledger below.\n\n`
        + lines);
    } else {
      tip.setAttribute('data-tip',
        'MCP server manifest not found — start the sift-ir-agent server (restart Claude Code).');
    }
  } catch (e) {
    tip.setAttribute('data-tip', 'MCP server catalogue unavailable.');
  }
}

/* ── Exec-gateway mode toggle ── */
function renderMode(m) {
  const el = document.getElementById('mode-toggle');
  if (!el) return;
  const mode = m === 'dev' ? 'dev' : 'forensic';
  el.className = 'mode-toggle ' + mode;
  el.dataset.mode = mode;
  el.querySelector('.mt-label').textContent = 'mode: ' + mode;
}
async function toggleMode() {
  const el = document.getElementById('mode-toggle');
  const cur = el.dataset.mode || 'forensic';
  const next = cur === 'dev' ? 'forensic' : 'dev';
  if (next === 'dev' && !confirm(
      'Switch exec gateway to DEV?\n\nThis enables curl/bash/rm and direct '
      + 'case-path access. Use only for /cases/project tooling, then switch '
      + 'back to forensic before case work.')) return;
  try {
    const r = await fetch('/api/mode', {method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({mode: next})});
    const j = await r.json();
    if (j.mode) renderMode(j.mode);
  } catch (e) { console.warn('[dashboard] mode toggle failed:', e.message); }
}

/* ── Poll loop ── */
async function refresh() {
  try {
    const [findings, theory, status, accuracy, mcp, coverage, entities, agentAct] = await Promise.all([
      get('/api/findings'),
      get('/api/theory'),
      get('/api/status'),
      get('/api/accuracy'),
      get('/api/mcp'),
      get('/api/coverage'),
      get('/api/entities'),
      get('/api/agent-activity'),
    ]);
    renderFindings(findings);
    renderEntities(entities);
    renderTheory(theory);
    renderStatus(status);
    renderAccuracy(accuracy);
    renderMcp(mcp);
    renderAgentActivity(agentAct);
    renderCoverage(coverage);
    updateAgentStatus(status, mcp);
    get('/api/mode').then(m => renderMode(m.mode)).catch(() => {});
  } catch (err) {
    console.warn('[dashboard] refresh error:', err.message);
    setAgentStatus('malfunction', {error: err.message});
  }
}

document.getElementById('findings-body').addEventListener('click', onFeedClick);
document.getElementById('entity-nav').addEventListener('click', onEntityNavClick);
document.getElementById('mode-toggle').addEventListener('click', toggleMode);
(() => {
  const accSec = document.getElementById('accuracy-section');
  if (!accSec) return;
  accSec.addEventListener('click', e => {
    const chip = e.target.closest('.acc-chip[data-acc]');
    if (!chip || !_acc || !_acc.ground_truth_present) return;
    const f = accuracyFilter(chip.dataset.acc);
    if (f) setFilter(f);
  });
})();
// Any "show all ✕" control (header chip or empty-state) clears the active filter.
document.addEventListener('click', e => {
  if (e.target.closest('.filter-clear')) setFilter(null);
});
(() => {
  const ge = document.getElementById('cov-escalation');
  ge.addEventListener('click', e => {
    const inst = e.target.closest('[data-install]');
    if (inst) { startInstall(inst.dataset.install); return; }
    const sn = e.target.closest('.gnode.stage');
    if (sn) {
      const stage = (sn.dataset.node || '').replace(/^stage:/, '');
      setFilter(stageFilter(stage));   // toggle handled inside setFilter
    }
  });
  ge.addEventListener('mouseover', e => {
    const n = e.target.closest('.gnode'); if (n) graphHover(n.dataset.node);
  });
  ge.addEventListener('mouseout', e => {
    const n = e.target.closest('.gnode'); if (n) graphClear();
  });
})();
loadPolicy();
// resume display if an install is already running (e.g. after a page reload)
(async () => {
  try {
    const st = await get('/api/install-status');
    if (st && st.name && st.state && st.state !== 'done' && st.state !== 'error') {
      installState[st.name] = st;
      if (_installPoll) clearInterval(_installPoll);
      _installPoll = setInterval(() => pollInstall(st.name), 1200);
    }
  } catch (e) {}
})();
refresh();
setInterval(refresh, POLL_MS);
</script>
</body>
</html>
"""

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="IR Agent Live Dashboard")
    parser.add_argument("--case", default="/cases/SRL-2015",
                        help="Path to the case root directory (default: /cases/SRL-2015)")
    parser.add_argument("--port", type=int, default=5000,
                        help="HTTP port (default: 5000)")
    parser.add_argument("--host", default="127.0.0.1",
                        help="Bind address (default: 127.0.0.1; use 0.0.0.0 for LAN/split-screen)")
    parser.add_argument("--mcp-log", default=None,
                        help=f"Exec-gateway audit log to read for MCP activity "
                             f"(default: {MCP_AUDIT_LOG})")
    args = parser.parse_args()

    case_dir = Path(args.case)
    mcp_log = Path(args.mcp_log) if args.mcp_log else Path(MCP_AUDIT_LOG)
    print(f"[dashboard] Case dir : {case_dir}")
    print(f"[dashboard] Analysis : {case_dir / 'analysis'}")
    print(f"[dashboard] MCP log  : {mcp_log}")
    print(f"[dashboard] Access   : http://{args.host}:{args.port}/")
    print("[dashboard] Ctrl+C to stop\n")

    app = create_app(case_dir, mcp_log=mcp_log)
    app.run(host=args.host, port=args.port, debug=False)
