# Agent Execution Logs — Vanko investigation

Structured, timestamped logs from the agent's autonomous run on the **Vanko** case
(insider data theft). All times UTC. Three complementary trails:

| File | What it is |
|------|-----------|
| `agent_activity.log` | The **investigative narrative** — JSONL, one entry per phase/finding/sub-agent. The structured reasoning trace (hypothesis → pivot → correction → judge → resolution), not a raw dump. |
| `mcp_tool_executions.log` | Every **typed MCP tool call** — `call` / `exec` / `result` records with the underlying command, exit code, and a **SHA-256 of the raw output** (chain of custody). This is what each finding traces back to. |
| `guardrail_enforcement.log` | The **exec-gateway decision trail** — every shell command `allow`/`deny` with a reason. Includes the forensic-mode denials that prove the guardrails are architectural, not advisory. |

This was a **single-agent** run (with spawned verification sub-agents); sub-agent
start/stop is recorded in `agent_activity.log`.

---

## The self-correction (Criterion 1) — in the logs, not just the video

`agent_activity.log` captures a genuine, naturally-triggered self-correction:

- **16:35:44** — hypothesis: `cnn.exe` is present in Prefetch but absent from the
  collection → "deleted-after-execution (anti-forensic)".
- **17:39:24** — **CORRECTION**: the Prefetch path hint read
  `\Program Files\WindowsApps\588E6FFA.CNNAppForWindows\CNN.EXE` — the benign CNN Store
  app, which CyLR simply hadn't collected. The agent **dropped its own hypothesis** and
  re-sequenced toward the real (insider-exfil) scenario.

The trigger was real tool output (`build_supertimeline` on Prefetch), not an injected error.

---

## Three-claim trace (Criterion 2 / 5) — pre-worked for you

Pick any finding from `findings_log.json`; each cites `artifact` + `offset` and resolves to
a tool execution in `mcp_tool_executions.log`. Three worked examples:

1. **Finding 1 — T1078, mapped `\\192.168.1.5\StarkResearch` as Z: (NTUSER.DAT:6227).**
   Produced by the `build_supertimeline` call on
   `.../Users/PC User/NTUSER.DAT` (see `mcp_tool_executions.log`), which wrote
   `ntuser/timeline.csv`; the share-mapping row was located by a `search_case_artifact`
   call (pattern `StarkResearch|Network\Z|MountPoints2`). Offset 6227 = the line in
   `ntuser/timeline.csv`.

2. **Finding 3 — T1560.001, 7-Zip `vacation photos.7z` (NTUSER.DAT:6279).**
   Produced by a `search_case_artifact` call over `ntuser/timeline.csv`
   (pattern `7-Zip|ArcHistory|vacation photos`) — the `HKCU\SOFTWARE\7-Zip` ArcHistory and
   the `.7z` shell-item rows.

3. **Finding 7 — T1567.002, Dropbox exfil (NTUSER.DAT:6288).**
   Produced by the `search_case_artifact` call at **17:54:11**
   (`fn: search_case_artifact`, pattern `...Dropbox|dropbox.com...`) — the IE DOMStorage
   `dropbox.com` and `HKCU\SOFTWARE\Dropbox\ks2` rows.

Every committed finding was additionally re-verified by an **independent judge** sub-agent
(`agent_activity.log` 17:52–17:55) before the gateway would accept it.

---

## Guardrails were tested for bypass (Criterion 4)

`guardrail_enforcement.log` contains real `deny` decisions, e.g.:

- `[forensic] denied pattern matched: 'nc'` — a raw-shell read attempt blocked.
- `[dev] denied pattern matched: 'rm -rf'` — destructive op blocked even in dev mode.
- `[forensic] too many arguments (>30)` — over-long command rejected.

Case data was reached **only** through the typed MCP server; the gateway adjudicated every
shell command first. The forensic→dev mode flips are visible in the trail (case work runs in
forensic; tooling/build work in dev).
