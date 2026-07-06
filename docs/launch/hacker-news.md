# Hacker News — Show HN

## When to post
Weekday, ~08:00–10:00 US Eastern (13:00–15:00 UTC). Avoid Fri/weekend. Post the
**published article link** (dev.to/Hashnode), not the raw GitHub repo — the story
travels further than the repo.

## Title (pick one; <80 chars, no clickbait — HN hates hype)

- `Show HN: I shipped an unauthenticated RCE in my own port scanner, then fixed it`
- `Show HN: Auditing my own Nmap web UI — an RCE chain and the fixes`

## First comment (post immediately after submitting — this is where you win HN)

> Author here. I built a FastAPI + React front end over Nmap, then audited it and
> found it was an unauthenticated RCE box. The chain was three individually
> "defensible" things stacked: no auth on the API, an upload endpoint that added
> its own files to the deep-dive allowlist, and Nmap argument injection (a target
> like `--script=/uploaded.nse` becomes a flag even with shell=False). Bandit also
> caught an XXE in the Nmap-XML parser I'd read straight past.
>
> Writeup has the before/after code; repo has the threat model and CI (pytest,
> Bandit, pip-audit, CodeQL). It's my own project — no third-party systems touched,
> and it's a dual-use tool so the docs are explicit about authorised-use-only.
>
> Happy to get torn apart on anything I still got wrong.

## Expectations (be honest with yourself)
HN is hit-or-miss; most Show HNs get little traction. The self-audit angle and a
tight first comment give you the best shot. If it stalls, that's normal — the
dev.to post and LinkedIn still do work for you. Do **not** re-post repeatedly or
ask for upvotes (both are against the rules and backfire).
