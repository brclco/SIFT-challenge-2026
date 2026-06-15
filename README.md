# Find Evil! — Autonomous DFIR Agent (SANS SIFT Challenge 2026)

An autonomous Digital Forensics & Incident Response (DFIR) agent for the SANS SIFT
Workstation. It triages real case data — disk images, live-response collections,
memory captures, Windows artifacts, event logs — at machine speed, and grounds every
conclusion in raw tool output. Built on **Protocol SIFT** and extending
[`marez8505/find-evil`](https://github.com/marez8505/find-evil), with a hard security
model that makes the guardrails **architectural, not prompt-based**.

> Status: private working repo for the challenge. Will be made public for submission.

## Why this design

LLM agents hallucinate and can be prompt-injected by evidence. So enforcement here does
**not** rely on the model behaving — it relies on processes the model cannot talk its way
past. Case data is reachable only through typed MCP functions; every shell command is
validated by a separate gateway process; findings cannot be committed until an independent
judge has verified them.

## The tollgates (enforcement checkpoints)

| # | Tollgate | Where it lives |
|---|----------|----------------|
| 1 | **MCP-only evidence access** — case data read only via typed forensic functions, never raw shell | `sift-mcp-server/server.py`, `~/.mcp.json` |
| 2 | **Gateway-validated exec** — every Bash command checked before it runs; fail-closed | `runclawd_exec_gateway.py` (localhost:12345), `hooks/pre_tool_use.sh` |
| 3 | **Forensic / dev mode** — forensic (default, fail-closed) for case work; dev for tooling | `.gateway_mode` |
| 4 | **Permission deny-list** — deny always wins (evidence writes, rm -rf/dd/curl/ssh, secret reads) | `settings.json` |
| 5 | **Forensic interpreter allowlist** — only the vetted `guardrails.py` may run as an interpreter in forensic mode | `runclawd_exec_gateway.py` |
| 6 | **Sanctioned write endpoints** — findings/theory/coverage/accuracy/manifest written only via the gateway | `/commit-findings`, `/commit-artifact` |
| 7 | **Mandatory judge gate** — `/commit-findings` rejects any finding lacking `judge_reviewed` + a `confirmed`/`flagged` verdict | `runclawd_exec_gateway.py` |
| 8 | **Independent judge + TTP cross-check** — a separate agent re-verifies each finding via MCP and validates its ATT&CK technique | `ttp_reference.json` |
| 9 | **Evidence integrity** — `/cases/<case>/evidence` is read-only (deny-list + gateway + filesystem) | `settings.json`, gateway |

See `docs/architecture.html` for the interactive diagram (hover any node for detail).

## Repository layout

```
sift-mcp-server/      Custom MCP server — 16 typed forensic functions over the SIFT toolchain
gateway/              runclawd_exec_gateway.py — the exec gateway (separate enforcement process)
agent/                guardrails.py + behavioral rules (CLAUDE.md) the agent runs under
hooks/                pre_tool_use.sh (Bash validation) · ensure_gateway.sh (launcher)
web/                  dashboard.py — live Flask dashboard (findings · theory · kill chain · coverage)
reference/            ttp_reference.json — canonical behaviour -> ATT&CK mapping
docs/                 architecture.html — interactive architecture / tollgate diagram
analysis-scripts/     generate_report.py — PDF incident-report generator
logs/                 agent execution logs (Vanko): narrative · MCP tool calls · guardrail decisions
```

## The 16 MCP forensic functions

`build_evidence_manifest` · `read_case_artifact` · `search_case_artifact` ·
`parse_event_logs` · `parse_amcache` · `parse_registry_persistence` ·
`hunt_lotl_behaviors` · `hunt_yara` · `analyze_disk_filesystem` ·
`carve_disk_artifacts` · `analyze_memory_processes` · `analyze_memory_network` ·
`analyze_memory_malfind` · `analyze_network_capture` · `query_mans` ·
`build_supertimeline`

Each caps its output and writes raw tool output to an audit directory.

## Outputs (challenge deliverables)

- **Findings log** (`findings_log.json`) — judge-gated, each finding traced to `artifact` + `offset`
- **Case theory** (`case_theory.json`) — overall intent (MALICE / SUSPICION / NEGLIGENCE) + narrative
- **Coverage report** (`coverage_report.json`) — data → tool → kill-chain-stage map
- **Accuracy report** (`accuracy_report.json`) — precision/recall/F1 vs ground truth + hallucination self-assessment
- **Execution logs** — gateway, MCP, and agent-activity audit trails with timestamps
- **PDF incident report** — stakeholder summary

## Quick start

```bash
# 1. Bring up the exec gateway (also auto-started per session via the SessionStart hook)
bash hooks/ensure_gateway.sh
curl -s http://127.0.0.1:12345/health

# 2. Launch the live dashboard for a case
python3 web/dashboard.py --case /cases/<CASE> --host 127.0.0.1 --port 5000

# 3. Start the agent against a case (forensic mode by default)
#    Case data is read only through the sift-ir-agent MCP server.

# 4. Generate the PDF incident report from the committed analysis artifacts
python3 analysis-scripts/generate_report.py --case /cases/<CASE>
```

A [sample report](docs/sample-incident-report.pdf) (Vanko case) is included.

## Submission documents

- [Project description](docs/PROJECT_DESCRIPTION.md) — what it does, how it's built, challenges, learnings
- [Dataset documentation](docs/DATASET.md) — sources, findings, reproducibility (Vanko / SRL-2015 / VIGIA)
- [Accuracy & evidence-integrity report](docs/ACCURACY.md) — false positives, coverage gaps, hallucination posture, spoliation resistance
- [Try it out](docs/TRY_IT_OUT.md) — setup for judges on a SIFT workstation
- [Architecture diagram](docs/architecture.html) — interactive; distinguishes architectural vs prompt-based guardrails

## Credits

Extends [`marez8505/find-evil`](https://github.com/marez8505/find-evil) and the Protocol SIFT
framework. Built for the SANS **Find Evil!** SIFT Challenge 2026.

## License

MIT — see [LICENSE](LICENSE).
