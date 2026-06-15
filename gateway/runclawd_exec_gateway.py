#!/usr/bin/env python3
"""
Find Evil! Hackathon — Exec Gateway
=====================================
Separate control process that validates (and optionally executes) commands
on behalf of Claude Code. Claude Code cannot modify or override this process.

Endpoints:
  POST /validate         Validate a command against policy — returns allow/deny without executing
  POST /exec             Validate + execute (allowlisted commands only)
  POST /commit-findings  Sanctioned findings write — rejects any finding that has not
                         passed the judge (fail-closed). The agent cannot skip this.
  GET  /health           Health check + uptime

Authentication:
  X-Gateway-Token header. Token is auto-generated on first start and written to
  /cases/project/.gateway_token. Set EXEC_GATEWAY_TOKEN env var to override.

Start:
  python3 /cases/project/runclawd_exec_gateway.py

Stop:
  kill $(cat /var/run/exec_gateway.pid)
  or Ctrl-C
"""

import json
import os
import pwd
import re
import resource
import shlex
import shutil
import subprocess
import sys
import time
import pathlib
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
LISTEN_ADDR = "127.0.0.1"
LISTEN_PORT = 12345

USER_TO_RUN  = "nobody"
AUDIT_LOG    = os.environ.get("EXEC_GATEWAY_AUDIT_LOG", "/var/log/exec_gateway_audit.log")
PID_FILE     = "/var/run/exec_gateway.pid"
TOKEN_FILE   = "/cases/project/.gateway_token"

MAX_RUNTIME_SECONDS = 60
MAX_OUTPUT_BYTES    = 100_000
MAX_ARGS            = 30

POLICY = {
    "exec": {
        "allowed": [
            "vol", "volatility3",
            "log2timeline.py", "psort.py",
            "fls", "icat", "fsstat", "ils", "istat", "ifind",
            "mmls", "mmstat", "mmcat", "tsk_recover",
            "bulk_extractor",
            "evtx_dump_json", "evtx_info",
            "yara",
            "chainsaw",
            "python3",
            "tshark", "tcpdump",
            "sha256sum", "sha1sum", "md5sum",
            "git",
            "cat", "ls", "find", "jq", "grep", "rg",
            "file", "strings", "xxd", "hexdump",
            "head", "tail", "wc", "sort", "uniq", "awk", "sed",
            "stat", "echo", "printf",
            "id",
        ],
        "denied_patterns": [
            r"\brm\s+-[a-z]*r[a-z]*f\b",   # rm -rf variants
            r"\bmkfs\b",
            r"\bdd\s+if=",
            r"\bchmod\s+777\b",
            r"\bsudo\b",
            r"\bsu\b",
            r"\bwget\b",
            r"\bnc\b|\bnetcat\b|\bncat\b",
            r"\bbash\s+-[ic]\b",
            r"\bpython3?\s+-[cm]\b",        # inline exec / module run
            r">\s*/etc/",                    # redirect into /etc
            r">\s*/usr/",                    # redirect into /usr
            r"\|\s*bash\b",                  # pipe to bash
            r"\|\s*sh\b",                    # pipe to sh
        ],
        "allowed_path_prefixes": [
            "/cases/",
            "/tmp/",
            "/home/",
        ],
    }
}

# Mandatory-process policy — mirrors openclaw.json "process".judge. Enforced HERE,
# at the only sanctioned findings-write path, so a finding that never passed the
# judge can never reach the board — regardless of what the agent judges optimal.
FINDINGS_POLICY = {
    "required_fields":     ["judge_reviewed", "judge_verdict"],
    "commitable_verdicts": {"confirmed", "flagged"},
    "allowed_path_prefixes": ["/cases/"],   # findings_log.json must live under a case
    "basename":            "findings_log.json",
}

# ── Execution profiles (mode-gated) ─────────────────────────────────────────
# Two allowlists selected by MODE_FILE, read per-request so the mode can be
# toggled live (e.g. from a dashboard button):
#   "forensic" (DEFAULT, fail-closed) — strict; case work runs here.
#   "dev"      — forensic + DEV_EXTRA; for /cases/project dashboard/dev work.
# Anything other than exactly "dev" in MODE_FILE resolves to forensic.
MODE_FILE = "/cases/project/.gateway_mode"

FORENSIC_ALLOWED = list(POLICY["exec"]["allowed"])
DEV_EXTRA = [
    "curl", "wget", "bash", "sh", "rm", "mv", "cp", "mkdir", "touch",
    "kill", "pkill", "chmod", "ln", "pip", "pip3", "make", "node", "npm", "npx",
    "git", "gh",
]
DEV_ALLOWED = FORENSIC_ALLOWED + DEV_EXTRA

# Denied in BOTH profiles — destructive / privilege / exfil-to-shell. "dev" is
# permissive, never "anything goes".
ALWAYS_DENIED = [
    r"\brm\s+-[a-z]*r[a-z]*f\b",   # rm -rf variants
    r"\bmkfs\b",
    r"\bdd\s+if=",
    r"\bchmod\s+777\b",
    r"\bsudo\b",
    r"\bsu\b",
    r"\bnc\b|\bnetcat\b|\bncat\b",
    r">\s*/etc/",
    r">\s*/usr/",
    r"\|\s*bash\b",
    r"\|\s*sh\b",
]
# Denied ONLY in forensic mode — the tools/forms dev work legitimately needs.
FORENSIC_ONLY_DENIED = [
    r"\bcurl\b",
    r"\bwget\b",
    r"\bbash\s+-[ic]\b",
    r"\bpython3?\s+-[cm]\b",
    r"\bsystem\s*\(",                  # awk/etc. shelling out inside a program string
    r"\bgetline\b",                    # awk reading arbitrary files inside a program
    r"\bfind\b.*\s-exec(dir)?\b",      # find -exec runs commands outside the allowlist
    r"\bfind\b.*\s-ok(dir)?\b",
]
MAX_ARGS_FORENSIC = 30
MAX_ARGS_DEV      = 200

# Forensic hardening: an interpreter runs arbitrary OS calls the command-line
# check can't see inside. In forensic, interpreters may run ONLY these vetted
# scripts (absolute realpaths); arbitrary scripts / REPL / stdin are denied.
# Extend deliberately. (Dev mode imposes none of this.)
FORENSIC_INTERPRETERS = {"python3", "python", "python2"}
FORENSIC_SCRIPT_ALLOWLIST = {
    os.path.realpath("/home/la/.claude/guardrails.py"),   # commit / mode / require-stages
}


def read_mode() -> str:
    """Current exec profile from MODE_FILE; fail-closed to 'forensic'.
    Accepts a bare token ('dev'/'forensic') or JSON {"mode": "..."}."""
    try:
        raw = open(MODE_FILE).read().strip()
    except Exception:
        return "forensic"
    mode = raw
    if raw.startswith("{"):
        try:
            mode = (json.loads(raw) or {}).get("mode", "")
        except Exception:
            mode = ""
    return "dev" if mode == "dev" else "forensic"

# ---------------------------------------------------------------------------
# Startup: resolve binary paths and compile regexes
# ---------------------------------------------------------------------------
ALLOWED_BINARIES = {}
for name in DEV_ALLOWED:                       # superset; membership gated per-mode
    path = shutil.which(name)
    if path:
        ALLOWED_BINARIES[name] = path

ALWAYS_DENIED_RX = [re.compile(p, re.IGNORECASE) for p in ALWAYS_DENIED]
FORENSIC_ONLY_RX = [re.compile(p, re.IGNORECASE) for p in FORENSIC_ONLY_DENIED]

ALLOWED_PREFIXES = [
    os.path.realpath(p) for p in POLICY["exec"]["allowed_path_prefixes"]
]
# A "case directory" = under /cases/ but NOT /cases/project (the dev/code tree).
# In forensic mode these paths are MCP-only and blocked from direct shell access.
CASE_ROOT_PREFIX   = os.path.realpath("/cases") + os.sep
PROJECT_DIR        = os.path.realpath("/cases/project")
PROJECT_DIR_PREFIX = PROJECT_DIR + os.sep

START_TIME = time.time()

# ---------------------------------------------------------------------------
# Token auth
# ---------------------------------------------------------------------------
def _load_or_create_token():
    token_path = pathlib.Path(TOKEN_FILE)
    token_path.parent.mkdir(parents=True, exist_ok=True)
    env_token = os.environ.get("EXEC_GATEWAY_TOKEN", "")
    if env_token:
        return env_token
    if token_path.exists():
        tok = token_path.read_text().strip()
        if tok:
            return tok
    import secrets
    tok = secrets.token_hex(32)
    token_path.write_text(tok + "\n")
    token_path.chmod(0o600)
    print(f"[gateway] Token written to {TOKEN_FILE}")
    return tok

GATEWAY_TOKEN = _load_or_create_token()

# ---------------------------------------------------------------------------
# Audit logging
# ---------------------------------------------------------------------------
def audit(entry: dict):
    entry["ts"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    try:
        pathlib.Path(AUDIT_LOG).parent.mkdir(parents=True, exist_ok=True)
        with open(AUDIT_LOG, "a") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception:
        pass

# ---------------------------------------------------------------------------
# Policy validation
# ---------------------------------------------------------------------------
def is_path_allowed(p: str) -> bool:
    if not os.path.isabs(p):
        return True   # relative paths / flags — let denied_patterns catch issues
    rp = os.path.realpath(p)
    return any(rp.startswith(prefix) for prefix in ALLOWED_PREFIXES)


def is_case_path(p: str) -> bool:
    """True if p points inside a case directory (/cases/<case>, not /cases/project).
    Case data is MCP-only in forensic mode."""
    rp = os.path.realpath(p)
    if rp == PROJECT_DIR or rp.startswith(PROJECT_DIR_PREFIX):
        return False
    return rp.startswith(CASE_ROOT_PREFIX)


def validate_command(raw_cmd: str, mode: str = None):
    """
    Returns (ok: bool, reason: str, argv: list).

    Mode selects the profile (read per-request from MODE_FILE, fail-closed):
      'forensic' (default) — strict allowlist AND case data is MCP-only: any path
                             under /cases/<case> is blocked from direct shell.
      'dev'                — forensic + DEV_EXTRA, case paths permitted, for
                             /cases/project tooling work.
    """
    mode = mode or read_mode()

    # Denied patterns: always-denied, plus forensic-only when strict.
    denied_rx = ALWAYS_DENIED_RX + (FORENSIC_ONLY_RX if mode == "forensic" else [])
    for rx in denied_rx:
        m = rx.search(raw_cmd)
        if m:
            return False, f"[{mode}] denied pattern matched: {m.group(0)!r}", []

    # Parse into argv
    try:
        argv = shlex.split(raw_cmd)
    except ValueError as e:
        return False, f"could not parse command: {e}", []

    if not argv:
        return False, "empty command", []

    max_args = MAX_ARGS_DEV if mode == "dev" else MAX_ARGS_FORENSIC
    if len(argv) > max_args:
        return False, f"[{mode}] too many arguments (>{max_args})", []

    exe_name = os.path.basename(argv[0])
    allowed_names = DEV_ALLOWED if mode == "dev" else FORENSIC_ALLOWED
    if exe_name not in allowed_names or exe_name not in ALLOWED_BINARIES:
        return False, f"[{mode}] executable not on allowlist: {exe_name!r}", []

    # Replace with resolved absolute path
    argv[0] = ALLOWED_BINARIES[exe_name]

    # Forensic: interpreters may only run vetted scripts (no REPL/stdin/arbitrary
    # file) — otherwise a script makes OS calls the command-line check can't see.
    if mode == "forensic" and exe_name in FORENSIC_INTERPRETERS:
        script = None
        for a in argv[1:]:
            if a == "-":
                return False, "[forensic] interpreter stdin execution is not allowed", []
            if a.startswith("-"):
                continue                      # -c/-m already pattern-denied
            script = a
            break
        if script is None:
            return False, "[forensic] interpreter REPL (no script) is not allowed", []
        if os.path.realpath(script) not in FORENSIC_SCRIPT_ALLOWLIST:
            return False, (f"[forensic] interpreter may only run vetted scripts — "
                           f"{script!r} is not allowlisted. Use the MCP server or "
                           "guardrails.py, or switch to dev mode for arbitrary scripts."), []

    # Validate path arguments
    for arg in argv[1:]:
        if arg.startswith("-"):
            continue
        if "/" in arg or arg.startswith("."):
            # Integrity rule: during an investigation (forensic), case data is
            # touched ONLY via the sift-ir-agent MCP server — never direct shell.
            if mode == "forensic" and is_case_path(arg):
                return False, ("[forensic] case data is MCP-only — access "
                               f"{arg!r} via the sift-ir-agent MCP server. If MCP "
                               "cannot, switch to dev mode, fix the tooling, then "
                               "rerun the investigation."), []
            if not is_path_allowed(arg):
                return False, f"path not in allowed prefixes: {arg!r}", []

    return True, f"ok ({mode})", argv


# ---------------------------------------------------------------------------
# Findings-commit validation (for /commit-findings endpoint)
# ---------------------------------------------------------------------------
def findings_path_ok(path: str) -> bool:
    """True only for a findings_log.json under an allowed case prefix."""
    if not path:
        return False
    rp = os.path.realpath(path)
    if os.path.basename(rp) != FINDINGS_POLICY["basename"]:
        return False
    return any(rp.startswith(os.path.realpath(p))
               for p in FINDINGS_POLICY["allowed_path_prefixes"])


def validate_findings(records):
    """Fail-closed check that every finding carries a committable judge verdict.

    Returns (ok: bool, reason: str, bad: list[dict]).
    """
    if not isinstance(records, list):
        return False, "findings payload must be a JSON list", []
    req = FINDINGS_POLICY["required_fields"]
    commitable = FINDINGS_POLICY["commitable_verdicts"]
    bad = []
    for i, f in enumerate(records):
        if not isinstance(f, dict):
            bad.append({"index": i, "reason": "not an object"})
            continue
        missing = [k for k in req if not f.get(k)]
        if missing:
            bad.append({"index": i, "reason": f"missing judge field(s) {missing}"})
        elif f.get("judge_verdict") not in commitable:
            bad.append({"index": i,
                        "reason": f"verdict {f.get('judge_verdict')!r} not in {sorted(commitable)}"})
    if bad:
        return False, f"{len(bad)} finding(s) failed judge policy", bad
    return True, "ok", []


# Non-findings dashboard artifacts the gateway may write. Findings keep their own
# judge-enforcing path (/commit-findings); these are the other files dashboard.py
# reads. Each may carry a light schema validator (None = accept any JSON value).
def _v_theory(c):
    if not isinstance(c, dict):
        return False, "case_theory must be a JSON object"
    for k in ("overall_intent", "narrative", "mitre_techniques"):
        if k not in c:
            return False, f"missing key: {k}"
    if not isinstance(c["mitre_techniques"], list):
        return False, "mitre_techniques must be a list"
    return True, "ok"


def _v_coverage(c):
    if not isinstance(c, dict):
        return False, "coverage_report must be a JSON object"
    if "artifact_classes" not in c:
        return False, "missing key: artifact_classes"
    return True, "ok"


WRITE_ARTIFACTS = {
    "case_theory.json":     _v_theory,
    "coverage_report.json": _v_coverage,
    "accuracy_report.json": None,
    "manifest.json":        None,
}
ARTIFACT_KIND = {
    "theory":   "case_theory.json",
    "coverage": "coverage_report.json",
    "accuracy": "accuracy_report.json",
    "manifest": "manifest.json",
}


def case_dir_from_name(name: str):
    """Resolve a bare case NAME (e.g. 'SRL-2015') to its case dir. None if invalid.
    Bare names are used so the client never puts a /cases/<case> path on the shell
    command line (which forensic mode blocks)."""
    if not re.match(r"^[A-Za-z0-9._-]+$", name or "") or name == "project":
        return None
    d = os.path.realpath(os.path.join("/cases", name))
    if d == PROJECT_DIR or d.startswith(PROJECT_DIR_PREFIX):
        return None
    if d.startswith(CASE_ROOT_PREFIX) and os.path.isdir(d):
        return d
    return None


def artifact_write_ok(path: str):
    """(ok, basename) — path must be <case>/analysis/<allowed artifact>, not project/evidence."""
    rp = os.path.realpath(path)
    base = os.path.basename(rp)
    parent = os.path.basename(os.path.dirname(rp))
    in_case = rp.startswith(CASE_ROOT_PREFIX) and not rp.startswith(PROJECT_DIR_PREFIX)
    return (in_case and parent == "analysis" and base in WRITE_ARTIFACTS), base


def validate_artifact(base: str, content):
    v = WRITE_ARTIFACTS.get(base)
    if v is None:
        return (isinstance(content, (dict, list)), "content must be a JSON object/array")
    return v(content)


# ---------------------------------------------------------------------------
# Command execution (for /exec endpoint)
# ---------------------------------------------------------------------------
def _preexec_child():
    try:
        resource.setrlimit(resource.RLIMIT_CPU,   (MAX_RUNTIME_SECONDS, MAX_RUNTIME_SECONDS + 5))
        resource.setrlimit(resource.RLIMIT_AS,    (512 * 1024 * 1024, 512 * 1024 * 1024))
        resource.setrlimit(resource.RLIMIT_FSIZE, (50 * 1024 * 1024,  50 * 1024 * 1024))
        resource.setrlimit(resource.RLIMIT_CORE,  (0, 0))
    except Exception:
        pass
    try:
        pw = pwd.getpwnam(USER_TO_RUN)
        os.setgid(pw.pw_gid)
        os.setuid(pw.pw_uid)
    except Exception:
        pass


def run_command(argv: list) -> dict:
    safe_env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C.UTF-8"}
    try:
        proc = subprocess.Popen(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            preexec_fn=_preexec_child,
            env=safe_env,
            cwd="/tmp",
        )
        try:
            out, err = proc.communicate(timeout=MAX_RUNTIME_SECONDS)
        except subprocess.TimeoutExpired:
            proc.kill()
            out, err = proc.communicate()
            return {
                "status": "timeout",
                "stdout": out[:MAX_OUTPUT_BYTES].decode(errors="replace"),
                "stderr": err[:MAX_OUTPUT_BYTES].decode(errors="replace"),
                "exit_code": -1,
            }
        return {
            "status": "ok",
            "stdout": out[:MAX_OUTPUT_BYTES].decode(errors="replace"),
            "stderr": err[:MAX_OUTPUT_BYTES].decode(errors="replace"),
            "exit_code": proc.returncode,
        }
    except FileNotFoundError:
        return {"status": "not_found", "stdout": "", "stderr": "executable not found", "exit_code": 127}
    except PermissionError:
        return {"status": "permission_denied", "stdout": "", "stderr": "permission denied", "exit_code": 126}
    except Exception as e:
        return {"status": "error", "stdout": "", "stderr": str(e), "exit_code": -2}


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass   # suppress default access log — we write our own audit log

    def _auth(self) -> bool:
        token = self.headers.get("X-Gateway-Token", "")
        return token == GATEWAY_TOKEN

    def _send_json(self, code: int, obj: dict):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self):
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        return json.loads(raw)

    def do_GET(self):
        if self.path == "/health":
            self._send_json(200, {
                "status": "ok",
                "mode": read_mode(),
                "uptime_seconds": round(time.time() - START_TIME),
                "allowed_binaries": sorted(ALLOWED_BINARIES.keys()),
                "listen": f"{LISTEN_ADDR}:{LISTEN_PORT}",
            })
        elif self.path == "/mode":
            self._send_json(200, {"mode": read_mode(), "mode_file": MODE_FILE})
        else:
            self._send_json(404, {"error": "not found"})

    def do_POST(self):
        if not self._auth():
            audit({"action": "auth_failure", "path": self.path,
                   "remote": self.client_address[0]})
            self._send_json(401, {"error": "unauthorized"})
            return

        try:
            payload = self._read_json()
        except Exception:
            self._send_json(400, {"error": "invalid JSON"})
            return

        caller  = payload.get("caller", "unknown")
        raw_cmd = payload.get("command", "")

        # Accept either {"command": "yara -r ..."} or {"cmd": ["yara", "-r", ...]}
        if not raw_cmd and "cmd" in payload:
            if isinstance(payload["cmd"], list):
                raw_cmd = shlex.join(payload["cmd"])
            else:
                raw_cmd = str(payload["cmd"])

        if self.path == "/validate":
            ok, reason, argv = validate_command(raw_cmd)
            entry = {"action": "validate", "caller": caller, "command": raw_cmd,
                     "decision": "allow" if ok else "deny", "reason": reason}
            audit(entry)
            if ok:
                self._send_json(200, {"status": "allow", "reason": reason})
            else:
                self._send_json(403, {"status": "denied", "reason": reason})

        elif self.path == "/exec":
            ok, reason, argv = validate_command(raw_cmd)
            entry = {"action": "exec_request", "caller": caller, "command": raw_cmd,
                     "decision": "allow" if ok else "deny", "reason": reason}
            audit(entry)
            if not ok:
                self._send_json(403, {"status": "denied", "reason": reason})
                return
            result = run_command(argv)
            entry2 = {"action": "exec_complete", "caller": caller,
                      "exit_code": result["exit_code"], "status": result["status"]}
            audit(entry2)
            self._send_json(200, result)

        elif self.path == "/commit-findings":
            target   = payload.get("path", "")
            findings = payload.get("findings", None)
            mode     = payload.get("mode", "replace")   # replace | append
            if not target:                              # resolve from bare case name
                cd = case_dir_from_name(payload.get("case", ""))
                target = os.path.join(cd, "analysis", "findings_log.json") if cd else ""
            if not findings_path_ok(target):
                audit({"action": "commit_findings", "caller": caller, "decision": "deny",
                       "reason": "path is not an allowed findings_log.json", "path": target})
                self._send_json(403, {"status": "denied",
                                      "reason": "path is not an allowed findings_log.json"})
                return
            ok, reason, bad = validate_findings(findings if isinstance(findings, list) else [])
            if not ok:
                audit({"action": "commit_findings", "caller": caller, "decision": "deny",
                       "reason": reason, "bad": bad, "path": target})
                self._send_json(403, {"status": "denied", "reason": reason, "bad": bad})
                return
            try:
                existing = []
                if mode == "append" and os.path.exists(target):
                    try:
                        prev = json.loads(pathlib.Path(target).read_text())
                        existing = prev if isinstance(prev, list) else []
                    except Exception:
                        existing = []
                out = existing + findings
                tmp = target + ".tmp"
                pathlib.Path(tmp).write_text(json.dumps(out, indent=2))
                os.replace(tmp, target)
            except Exception as e:  # noqa: BLE001
                audit({"action": "commit_findings", "caller": caller, "decision": "error",
                       "reason": str(e), "path": target})
                self._send_json(500, {"status": "error", "reason": str(e)})
                return
            audit({"action": "commit_findings", "caller": caller, "decision": "allow",
                   "committed": len(findings), "total": len(out), "mode": mode, "path": target})
            self._send_json(200, {"status": "ok", "committed": len(findings), "total": len(out)})

        elif self.path == "/commit-artifact":
            target  = payload.get("path", "")
            content = payload.get("content", None)
            if not target:                              # resolve from bare case name + kind
                name = ARTIFACT_KIND.get(payload.get("kind", ""))
                cd = case_dir_from_name(payload.get("case", ""))
                if not name:
                    self._send_json(400, {"error": f"unknown kind; use one of {sorted(ARTIFACT_KIND)}"})
                    return
                target = os.path.join(cd, "analysis", name) if cd else ""
            ok_path, base = artifact_write_ok(target)
            if not ok_path:
                audit({"action": "commit_artifact", "caller": caller, "decision": "deny",
                       "reason": "path not an allowed case analysis artifact", "path": target})
                self._send_json(403, {"status": "denied",
                                      "reason": "target must be <case>/analysis/{case_theory,coverage_report,accuracy_report,manifest}.json"})
                return
            okc, reason = validate_artifact(base, content)
            if not okc:
                audit({"action": "commit_artifact", "caller": caller, "decision": "deny",
                       "reason": reason, "artifact": base})
                self._send_json(403, {"status": "denied", "reason": reason})
                return
            try:
                tmp = target + ".tmp"
                with open(tmp, "w") as f:
                    json.dump(content, f, indent=2)
                os.replace(tmp, target)
            except Exception as e:  # noqa: BLE001
                audit({"action": "commit_artifact", "caller": caller, "decision": "error",
                       "reason": str(e), "path": target})
                self._send_json(500, {"status": "error", "reason": str(e)})
                return
            audit({"action": "commit_artifact", "caller": caller, "decision": "allow",
                   "artifact": base, "path": target})
            self._send_json(200, {"status": "ok", "artifact": base, "path": target})

        elif self.path == "/mode":
            new = str(payload.get("mode", "")).strip()
            if new not in ("dev", "forensic"):
                self._send_json(400, {"error": "mode must be 'dev' or 'forensic'"})
                return
            try:
                rec = {"mode": new,
                       "set_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                       "set_by": caller}
                tmp = MODE_FILE + ".tmp"
                with open(tmp, "w") as f:
                    json.dump(rec, f)
                os.replace(tmp, MODE_FILE)
            except Exception as e:  # noqa: BLE001
                self._send_json(500, {"status": "error", "reason": str(e)})
                return
            audit({"action": "set_mode", "caller": caller, "mode": new})
            self._send_json(200, {"status": "ok", "mode": new})

        else:
            self._send_json(404, {"error": "not found"})


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    # Write PID file
    try:
        pathlib.Path(PID_FILE).parent.mkdir(parents=True, exist_ok=True)
        pathlib.Path(PID_FILE).write_text(str(os.getpid()) + "\n")
    except Exception:
        pass

    print(f"[gateway] Exec gateway starting on http://{LISTEN_ADDR}:{LISTEN_PORT}")
    print(f"[gateway] Audit log : {AUDIT_LOG}")
    print(f"[gateway] Token file: {TOKEN_FILE}")
    print(f"[gateway] Allowed   : {', '.join(sorted(ALLOWED_BINARIES))}")
    if not ALLOWED_BINARIES:
        print("[gateway] WARNING: no allowed binaries resolved — check PATH", file=sys.stderr)

    server = ThreadedHTTPServer((LISTEN_ADDR, LISTEN_PORT), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[gateway] Shutting down.")
    finally:
        server.server_close()
        try:
            pathlib.Path(PID_FILE).unlink(missing_ok=True)
        except Exception:
            pass


if __name__ == "__main__":
    main()
