# Reddit — r/netsec (and fallbacks)

## Read this first — r/netsec is strict
r/netsec removes low-effort self-promotion and "I made a tool" posts. It rewards
**technical writeups with real content**. Your post must be the *article link*,
and the writeup has to stand on its own as instructive. Even then it may not land
— that's the subreddit, not you.

- Submit the **published article URL** (dev.to/Hashnode), not the GitHub repo.
- Post under a technical title (below). No "please star my repo."
- Follow the subreddit's posting rules / flair requirements at submission time.
- Engage seriously in comments; netsec will test your understanding.

## Title options (technical, specific — this is what r/netsec upvotes)

- `Chaining "defensible" bugs into unauthenticated RCE in a FastAPI + Nmap web UI`
- `Nmap argument injection with shell=False: how a scan target becomes --script=`
- `Why an upload endpoint that adds files to its own allowlist is game over`

## If r/netsec removes it, these are more forgiving fallbacks
- **r/Python** — frame around FastAPI/subprocess/defusedxml lessons.
- **r/devops** or **r/selfhosted** — frame around hardening a self-hosted tool.
- **r/cybersecurity** — broader, less strict than r/netsec.

## Optional self-post body (only where self-posts are allowed; keep it substance-first)

> I built a web UI over Nmap, then audited my own code and found an unauthenticated
> RCE chain. Writeup covers three composed bugs — missing auth, an allowlist an
> upload could extend, and Nmap argument injection that works even with
> `shell=False` (`--script=` as a target) — plus an XXE in the scan-XML parser that
> Bandit caught and my manual review missed. Includes before/after code, a threat
> model, and CI (Bandit/pip-audit/CodeQL).
>
> It's my own project; nothing external was touched. Feedback on anything I got
> wrong is welcome. [link to article]
