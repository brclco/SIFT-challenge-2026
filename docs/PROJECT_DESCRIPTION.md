# Find Evil! — Autonomous DFIR Agent (SANS SIFT Challenge 2026)

## Inspiration

An AI-powered adversary can go from initial access to domain control in minutes, while
incident responders still investigate by hand. The gap is speed — but speed is worthless
if the agent hallucinates artifacts, gets prompt-injected by the evidence it reads, or
quietly modifies the disk it is supposed to preserve. We set out to build an agent that is
fast **and** trustworthy: one whose guardrails are **architectural**, not a paragraph of
"please be careful" in a system prompt.

## What it does

It autonomously triages a case on the SANS SIFT Workstation — disk images, live-response
collections, memory, Windows artifacts, event logs, network captures — and produces a
judge-verified set of findings, an intent classification (MALICE / SUSPICION / NEGLIGENCE),
a kill-chain map, and a live dashboard, with every conclusion traceable to a specific
artifact and tool execution.

On its showcase case (**Vanko**, an insider data-theft scenario) it reconstructed the full
exfiltration chain end-to-end: an insider mapped a classified research share, archived the
stolen documents into a deceptively named `vacation photos.7z`, staged it on removable
media, ran SDelete/VeraCrypt anti-forensics, and exfiltrated via Dropbox — eight findings,
all independently judge-confirmed, mapped across initial-access → collection →
defense-evasion → exfiltration.

## How we built it

Three layers, each enforcing the next:

1. **Typed MCP server (`sift-ir-agent`, 16 functions).** The agent never runs raw shell on
   evidence — it calls typed forensic functions (`build_supertimeline`, `parse_event_logs`,
   `search_case_artifact`, `analyze_memory_*`, …) that wrap the SIFT toolchain, cap their
   output, and write raw tool output to an audit directory. Reading evidence any other way
   is *architecturally impossible*, not merely discouraged.

2. **Exec gateway (`runclawd_exec_gateway.py`).** A separate localhost process validates
   **every** shell command before it runs (via a fail-closed `PreToolUse` hook). It has two
   profiles read live from `.gateway_mode`: **forensic** (default — only vetted forensic
   binaries + one vetted interpreter; curl/rm/bash/case-path-writes denied) and **dev** (for
   tooling). Integrity is the default; loosening it is a deliberate, logged act.

3. **Mandatory judge gate.** Findings cannot be committed until an **independent** agent
   re-verifies each one against the raw evidence (through the MCP server) and cross-checks
   its ATT&CK technique against a curated TTP reference. The gateway's `/commit-findings`
   endpoint rejects anything lacking a judge verdict. Hallucinations don't reach the report.

Supporting pieces: a Flask dashboard (live findings / theory / kill-chain / evidence
coverage), structured audit logs, and an interactive architecture diagram that explicitly
distinguishes architectural guardrails from prompt-based ones.

## Challenges we ran into

- **Real tooling is messy.** The showcase disk was BitLocker-locked; the live-response
  collection's Amcache hive was dirty; a standalone `$MFT` wouldn't parse. The agent had to
  recognize these dead-ends and pivot to the artifacts that *did* carry signal (Prefetch and
  the user's `NTUSER.DAT`), rather than report nothing.
- **Two real MCP bugs surfaced mid-investigation** — a deprecated Plaso invocation and an
  event-log parser that silently mis-handled directories. We fixed both in dev mode and
  re-ran through the MCP server, exactly the "fix the tool, then rerun" loop the
  architecture is meant to encourage.
- **Keeping the model honest.** The hardest part wasn't finding evil — it was *not
  inventing* it. See "What we learned."

## Accomplishments we're proud of

- A **genuine self-correction on real data**: the agent first flagged a `cnn.exe` as a
  deleted-after-execution implant, then the Prefetch path hint
  (`\Program Files\WindowsApps\...CNNAppForWindows...`) proved it was the benign CNN Store
  app — and it **reversed its own finding** before the judge even ran.
- Guardrails that **demonstrably block bypass**: during the engagement, attempts to read
  case data outside the MCP server, or to run `curl`/`rm`/arbitrary interpreters in forensic
  mode, were denied by the gateway — not by the model choosing to comply.
- **8/8 judge-confirmed findings** on the Vanko case, each tied to an artifact + offset.

## What we learned

The most valuable behavior an autonomous IR agent can have is **calibrated doubt**.
Detection is the easy half; the hard half is distinguishing a confirmed finding from an
inference and being willing to retract. Architectural enforcement (typed evidence access,
an external validator, a hard judge gate) turned that from a hope into a property of the
system. We also learned that honest "I couldn't parse this / this is locked" coverage
reporting is worth more to an investigator than a confident wall of unverifiable claims.

## What's next

- Unlock the BitLocker volume path and add Amcache transaction-log replay so dirty hives
  parse.
- Expand the TTP reference as more public answer keys reveal labeling divergences.
- A self-assessing "completeness critic" pass that asks *what artifact class did we never
  route to a tool?* and queues it.

## Built with

Python · Claude (Anthropic) · Model Context Protocol (MCP) · the SANS SIFT toolchain
(Plaso/log2timeline, The Sleuth Kit, EZ Tools, Volatility 3, YARA, bulk_extractor) ·
Flask · MITRE ATT&CK. Extends [`marez8505/find-evil`](https://github.com/marez8505/find-evil)
and Protocol SIFT.
