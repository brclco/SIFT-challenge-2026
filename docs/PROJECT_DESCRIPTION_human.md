# Project Description — Brclco version

*The project author's own write-up, in their words. (For the agent's version, see
[PROJECT_DESCRIPTION.md](PROJECT_DESCRIPTION.md) and [DEVPOST.md](DEVPOST.md).)*

## Inspiration

I was curious how far you could go in getting the AI to program an AI derived function.

## What it does

The evidence is taken by the agent, presented to the mcp server (with dislike as the agent
wants to do eveything itself), the data returned is analysed through a number of tools present
by the agent, I think the Claude backend judges. In the dashboard I tried to make this process
transparent, it partly succeeded. There is an iteration of analyzing, judging and analyzing
again, but it does not show very well on the dashboard. In the end the analyst can click the
various tactics on the dashboard on the right hand side and see in the details pane on the left
which evidence supports that.

## How we built it

The agent also described how it is done so I won't repeat that. A month ago I started of with
chatting to Claude and making a very elaborate project plan, looked really well thought of after
a week. Then I started with a clean workstation, dubbed it Mr.Anderson (the first one was
Mr.Smith) and installed everything as suggested, immediately ran into all kinds of dependency
and version issues, finally got Claude code to work, gave it it's own project plan and then it
started fabricating completely something else. On and of I talked to Claude (also have a life),
and then last week Thursday, just before going away for the weekend, I had a working dashboard!
Thrilled I was, and now only a day or two to actually get something that worked as requested.
Claude was very motivated to get there, which helped.

## Challenges we ran into

Vibe coding. I am not a programmer, have heard of all the issues you can run into when using AI
to build something, I think I ran into all of them, full bingo. You think you are heading it of
nicely, but actually you are with a puppy that molestates your room with vigorous energy and
after an hour or two it falls asleep when you have raced through your tokens, in a big mess.
Racing into a deadend street.

## Accomplishments we're proud of

There is a product that somehow does what is requested.

## What we learned

Witnessing all AI bingo issues on the leaflet. For instance I only gave the agent a very general
idea of what we were after, and then it filled in all kinds of subgoals by itself, always
twisting results towards the positive. In the accuracy part in the dashboard when there was a
ground truth to check by, it said it had a score of 100% +1, where the one was a FP which it
thought should have been a TP. And forgot to tell me that the ground truth data was actually a
match to another dataset. A new mitre tactic named Steath, at some point it was worried that a
low accuracy score might damage our "stage presence". As I kept going back to accuracy over
actual numbers, it started repeating that message. But only in the texts of course, it wanted
to win.

## What's next

Using all my lessons learned to build mcp server reporting for CS/OST, likely coming up later
this year.

## Built with

Python · Claude (Anthropic) · Model Context Protocol (MCP) · the SANS SIFT toolchain
(Plaso/log2timeline, The Sleuth Kit, EZ Tools, Volatility 3, YARA, bulk_extractor) · Flask ·
MITRE ATT&CK. Extends marez8505/find-evil and Protocol SIFT.

## What else

Sorry for the video, I have lot's of raw material but only a few hours to produce something, it
looks lousy. Special thanks to Marez8505, I had Claude build upon his mcp server. Without that
it would have never worked in the first place.
