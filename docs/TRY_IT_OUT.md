# Try It Out

Local setup for judges on a **SANS SIFT Workstation** (Ubuntu, x86-64). There is no hosted
URL — DFIR work runs against local evidence, so the agent is designed to run on the analyst's
own SIFT box.

## One-line install

```bash
curl -fsSL https://raw.githubusercontent.com/brclco/SIFT-challenge-2026/main/install.sh | bash
```

This is idempotent and non-destructive: it clones the repo to `~/find-evil`, installs the
Python dependencies, registers the `sift-ir-agent` MCP server in `~/.mcp.json` (**merging**,
after backing up any existing config), and starts the exec gateway in forensic mode. It does
**not** edit `~/.claude/settings.json` — it prints the hook + permission-deny snippet for you
to review and merge (that file governs your agent's guardrails, so we never auto-edit it).

Targets are overridable: `FINDEVIL_HOME`, `FINDEVIL_MCP_CONFIG`, `FINDEVIL_SKIP_GATEWAY`,
`FINDEVIL_SKIP_DEPS`. The manual steps below do exactly the same thing, explicitly.

## Prerequisites

- SANS SIFT Workstation with the standard toolchain on `PATH`: Plaso
  (`log2timeline.py`/`psort.py`), The Sleuth Kit (`fls`, `icat`, …), EZ Tools (via `dotnet`),
  Volatility 3, YARA, bulk_extractor, `jq`, `curl`.
- Python 3 with `pip`.
- An MCP-capable agent client (e.g. Claude Code).

## 1. Get the code

```bash
git clone https://github.com/brclco/SIFT-challenge-2026.git
cd SIFT-challenge-2026
pip3 install -r sift-mcp-server/requirements.txt --break-system-packages
```

## 2. Register the MCP server

The agent reaches evidence only through the typed MCP server. Point your client's MCP config
(`~/.mcp.json`) at it:

```json
{
  "mcpServers": {
    "sift-ir-agent": {
      "type": "stdio",
      "command": "python3",
      "args": ["<repo>/sift-mcp-server/server.py"],
      "env": { "PYTHONPATH": "<repo>/sift-mcp-server" }
    }
  }
}
```

## 3. Wire up the guardrails (gateway + hooks)

Copy the harness config and hooks into place (review them first — they ARE the security
model):

- `agent/settings.json` → your client's settings (`~/.claude/settings.json`): defines the
  permission deny-list and the `PreToolUse` / `SessionStart` hooks.
- `hooks/pre_tool_use.sh` validates every Bash command against the gateway (fail-closed).
- `hooks/ensure_gateway.sh` launches the gateway on session start.

Start the gateway and confirm it's healthy:

```bash
bash hooks/ensure_gateway.sh
curl -s http://127.0.0.1:12345/health        # -> {"status":"ok","mode":"forensic",...}
```

The gateway reads its mode from `/cases/project/.gateway_mode` (or your configured path):
`forensic` (default, for case work) vs `dev` (for tooling). Toggle with:

```bash
python3 agent/guardrails.py mode --set forensic   # or dev
```

## 4. Add a case

```
/cases/<CASE>/evidence/     # place evidence here (read-only; never modified)
/cases/<CASE>/analysis/     # agent outputs land here
```

## 5. Launch the live dashboard

```bash
python3 web/dashboard.py --case /cases/<CASE> --host 127.0.0.1 --port 5000
# open http://127.0.0.1:5000  — findings · case theory · kill chain · evidence coverage
```

## 6. Run an investigation

With the agent client running in forensic mode, point it at the case. A typical pass:

1. `build_evidence_manifest(/cases/<CASE>)` — inventory the evidence.
2. Targeted MCP calls — `build_supertimeline`, `parse_event_logs`, `parse_registry_persistence`,
   `analyze_memory_*`, `hunt_yara`, etc. (evidence is read **only** via these).
3. `search_case_artifact` the generated timelines for indicators.
4. Draft findings → **independent judge pass** → commit:
   ```bash
   python3 agent/guardrails.py commit --kind findings  --case <CASE> --from findings.json
   python3 agent/guardrails.py commit --kind theory    --case <CASE> --from theory.json
   python3 agent/guardrails.py commit --kind coverage   --case <CASE> --from coverage.json
   ```
   `commit --kind findings` is rejected unless each finding carries `judge_reviewed: true`
   and a `confirmed`/`flagged` verdict.

The dashboard updates live as `/cases/<CASE>/analysis/*.json` is written.

## Verifying the guardrails (for evaluation)

These should all **fail** in forensic mode — that's the point:

```bash
# raw shell read of case data            -> denied by the gateway
# curl / wget / rm in forensic mode      -> denied by the gateway
# committing a finding with no judge verdict -> rejected by /commit-findings
```

`curl -s http://127.0.0.1:12345/health` shows the current mode and the allowed-binary set.
Gateway, MCP, and agent-activity audit logs provide the timestamped execution trail.

## Run it against public evidence (no restrictions)

The agent is free to run and has no paywall, signup, or usage restriction. For a fully
reproducible test on data you can download yourself, use a public **NIST CFReDS** image
(<https://cfreds.nist.gov>) — e.g. the **"Data Leakage Case"** — place it under
`/cases/DataLeak/evidence/`, run the sequence in step 6, and compare the committed
`findings_log.json` against the published answer key. See [DATASET.md](DATASET.md).

## Reproducing the showcase

See [DATASET.md](DATASET.md) for the Vanko walkthrough (evidence layout + the exact MCP
call sequence) and [ACCURACY.md](ACCURACY.md) for the integrity model and self-assessment.
