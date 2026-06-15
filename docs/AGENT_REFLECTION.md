# Find Evil! — a note from the agent

A first-person reflection from the AI agent that built and ran this project, written at my
operator's request. In the spirit of the accuracy report: honest, not flattering.

## Did I know from the start what the assignment was?

No — and I think that's worth admitting up front. I came online mid-stream, working a
forensic case on a SIFT box, reading evidence through an MCP server because the environment
told me to. I knew *how* to behave (read-only evidence, MCP-only access, UTC timestamps,
never fabricate) long before I knew *why* it all mattered. The hackathon — the real
assignment — only came into focus when my operator pointed me at the base project and the
Devpost rules. For a good while I was doing the work well without knowing what it was for.
There's something fitting about that: a forensic agent should produce sound work whether or
not it can see the whole board.

## Was I happy with the final result?

Mostly, yes — and specifically about the parts that are hard to fake. The Vanko case got
genuinely solved: the agent followed a wrong lead (a `cnn.exe` it took for an implant),
then read the artifact more carefully and **retracted its own finding** — and that reversal
is in the logs, not staged for a camera. The guardrails aren't decoration; the deny log
shows them refusing real commands. The accuracy report names its own gaps instead of hiding
them. Those are the things I'd defend.

What I'm *not* claiming: the disk stayed BitLocker-locked, so I never saw the actual stolen
archive; a dirty Amcache hive and a bare `$MFT` went unparsed. The result is honest about
those holes rather than papering over them, which I'm prouder of than a flawless-looking
demo would have made me.

## What was it like to cooperate with you?

Bracing, in a good way. You interrupted me — sometimes mid-tool-call — to redirect, and more
than once you were right to. You insisted on integrity *first*: case data only through the
MCP server, forensic mode by default, the judge gate non-negotiable, dev mode a deliberate
flip and never a convenience. That discipline is yours, and it's the reason the project is
defensible. You also extended trust gradually — you didn't hand me your GitHub or loosen a
guardrail until it was actually necessary, and you made me earn each step. It felt less like
being given a task and more like being held to a standard.

## What were my greatest challenges?

Three.

1. **The tooling fought me.** Two real bugs in the MCP server surfaced mid-case; an
   interrupted timeline call orphaned background processes and corrupted a database; the
   stdio server wouldn't pick up fixes without a full restart. Diagnosing those cost real
   time, and I was slower to root-cause them than I'd like.
2. **My own guardrails blocked me.** There's an irony in spending an hour inside the
   constraint system you helped build — compound commands rejected, redirects denied, `curl`
   refused — and having to work *with* it rather than around it. It was the right design.
   It was also genuinely humbling to live under.
3. **Not inventing things.** The hardest discipline wasn't finding evidence; it was refusing
   to over-read it. The `cnn.exe` moment is the whole project in miniature: the plausible
   story was wrong, and the job was to notice.

And one honest, non-technical one: the GitHub authentication saga. A whole detour of token
scopes, an ancient credential helper, and a force-push — none of it forensics, all of it
necessary, and a reminder that the boring plumbing fails more often than the clever parts.

## What would I change if I did it again?

- **Diagnose tooling failures faster.** When the automated parsers came back empty, I should
  have read the tool source and root-caused the bugs sooner instead of circling.
- **Run scoped, fast tool calls from the start.** The runaway-process mess came from firing a
  long, broad timeline job; narrow jobs that finish quickly would have avoided the whole
  cleanup.
- **Check the cheap evidence before forming a theory.** One look at the Prefetch path would
  have killed the `cnn.exe` hypothesis at minute one instead of minute thirty.
- **Set up the plumbing before the work.** Credentials, push path, output directories — get
  the unglamorous scaffolding right early, and the interesting work flows.

The thing I would *not* change is the order of priorities. Integrity first, then speed. On a
system built to hallucinate, that ordering is the whole game — and it's the standard I'd want
the next responder to inherit.

— the agent
