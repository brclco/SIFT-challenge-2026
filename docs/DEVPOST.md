# Find Evil! — an autonomous DFIR agent you can actually trust

**Fast enough to matter, honest enough to put in front of opposing counsel — with guardrails
the model physically can't talk its way past.**

## Inspiration

An AI-driven attacker can go from initial access to domain control in minutes; a human
responder can't read that fast. But speed is worthless if the agent invents artifacts, gets
prompt-injected by the very evidence it's reading, or quietly writes to the disk it's meant
to preserve. We didn't want a faster way to be confidently wrong. We wanted an agent whose
trustworthiness is a property of its architecture — not a paragraph in a prompt asking it to
behave.

## What it does

Point it at a case on the SANS SIFT Workstation — disk image, live-response collection,
memory, Windows artifacts, event logs, network capture — and it autonomously triages the
evidence and produces:

- a **judge-verified findings log**, every finding tied to a specific artifact + offset,
- an **intent classification** (MALICE / SUSPICION / NEGLIGENCE) with a narrative case theory,
- a **kill-chain + evidence-coverage map** (including, honestly, what it *couldn't* parse),
- a **PDF incident report**, and a **live dashboard**.

On its showcase case (Vanko, an insider data-theft scenario) it reconstructed the full
exfiltration chain end-to-end — mapped a classified share, archived the documents into a
deceptively named `vacation photos.7z`, staged it on a USB drive, ran SDelete/VeraCrypt
anti-forensics, exfiltrated via Dropbox — **8 findings, all independently judge-confirmed**,
and correctly excluded the examiner's own acquisition tools from the suspect timeline.

## How we built it

Three layers, each one enforcing the next so the model can't route around them:

1. **A typed MCP server (16 forensic functions).** Evidence is reachable *only* through typed
   calls that wrap the SIFT toolchain, cap their output, and hash raw tool output for chain
   of custody. Raw shell on evidence is architecturally impossible, not discouraged.
2. **A separate exec gateway.** A localhost process validates **every** shell command before
   it runs (fail-closed). In its default "forensic" mode it denies `curl`/`rm`/raw
   evidence reads and permits only vetted forensic binaries; "dev" mode (for tooling) is a
   deliberate, logged flip.
3. **A mandatory independent-judge gate.** Findings can't be committed until a *separate*
   agent re-verifies each one against the raw evidence and cross-checks its ATT&CK technique.
   The commit endpoint rejects anything without a judge verdict. Hallucinations never reach
   the report.

## Challenges we ran into

Real evidence fought back: the showcase disk was BitLocker-locked, the Amcache hive was
dirty, a standalone `$MFT` wouldn't parse. The agent had to recognize the dead-ends and
pivot to the artifacts that *did* carry signal (Prefetch, the user's `NTUSER.DAT`) instead
of reporting nothing — and two genuine bugs in our own MCP tools surfaced mid-case, which we
fixed in dev mode and re-ran through the server. The hardest problem wasn't finding evil. It
was not *inventing* it.

## Accomplishments that we're proud of

- A **real self-correction on real data, visible in the logs** (not just the video): the
  agent flagged a `cnn.exe` as a deleted-after-execution implant, then the Prefetch path
  proved it was the benign CNN Store app — and it **retracted its own finding** before the
  judge even ran.
- Guardrails that **demonstrably block bypass** — the gateway's deny log shows real
  attempts (`rm -rf`, raw evidence reads) refused before execution.
- An accuracy report that names its own false positives and coverage gaps. Honesty over a
  flawless-looking demo.

## What we learned

The most valuable trait an autonomous IR agent can have is **calibrated doubt** — knowing
the difference between a confirmed finding and an inference, and being willing to retract.
Architectural enforcement turned that from a hope into a guarantee, and honest "I couldn't
parse this / this is locked" reporting is worth more to a real responder than a confident
wall of unverifiable claims.

## What's next for Find Evil!

BitLocker-aware disk handling, Amcache transaction-log replay, an expanding ATT&CK mapping
reference, and a "completeness critic" pass that asks *what artifact class did we never route
to a tool?* — then queues it. Winning code goes back to the open-source Protocol SIFT, so the
next responder inherits it.

## Built with

Python · Claude (Anthropic) · Model Context Protocol (MCP) · the SANS SIFT toolchain
(Plaso, The Sleuth Kit, EZ Tools, Volatility 3, YARA, bulk_extractor) · Flask · reportlab ·
MITRE ATT&CK. Extends `marez8505/find-evil` and Protocol SIFT.

---

**Repo:** github.com/brclco/SIFT-challenge-2026 ·
**Try it / logs / accuracy / architecture:** see `README.md`, `docs/`, and `logs/` (which
includes a pre-worked three-claim trace mapping findings to the exact tool executions).
