# huntr CVE hunt — target selection + sink map (Python / AI-ML)

huntr (Protect AI) is a **CNA**: a validated report gets a **bounty + a CVE**.
It fits your Python strength because the AI/ML OSS ecosystem is almost entirely
Python. Bounties are paid monthly (~25th) via Stripe.

**Two programs:**
- **OSV (Open Source Vulnerabilities)** — bugs in AI/ML apps & libraries (web
  dashboards, pipeline tools, model registries). This is your main track.
- **MFV (Model File Vulnerabilities)** — malicious model files that execute code
  on load (pickle-based formats). A distinct, high-value niche.

> **Confirm scope first.** The live in-scope list and per-project bounties are at
> **huntr.com/bounties**. Only hunt projects currently listed as in-scope, follow
> **huntr.com/guidelines**, and test **locally on software you downloaded** —
> never against anyone's hosted instance.

---

## Why AI/ML apps are a rich, beginner-friendly CVE surface
Many are young web apps (dashboards, experiment trackers, model servers) that
grew fast and skipped hardening — exactly the class of bug you already understand
from your own project (auth gaps, path traversal, unsafe deserialisation). The
same review instincts transfer directly.

## Candidate categories (confirm each is in-scope on huntr before starting)
Pick **one** young-but-used project with a web UI or file-handling surface.
Well-known Python AI/ML OSS categories that historically carry these bug classes:

- **Experiment trackers / model registries** — artifact download/upload,
  path handling, auth on the dashboard.
- **Model-serving / inference servers** — model load paths, deserialisation,
  file endpoints.
- **LLM app frameworks / pipeline tools** — template rendering (SSTI), tool/agent
  file access, SSRF via URL fetchers.
- **Data / MLOps dashboards** — classic web bugs: IDOR, path traversal, missing
  authz on API routes.

(Don't take a name from me as "in-scope" — match against huntr's current list.)

## Sink map — what to grep, per bug class

| Bug class (common in AI/ML apps) | Grep for | Then ask |
|---|---|---|
| Unsafe deserialisation / model-load RCE | `pickle.load(s)`, `torch.load`, `joblib.load`, `yaml.load`, `numpy.load(allow_pickle=True)`, `dill`, `__reduce__` | Does a user-supplied file/artifact reach this? |
| Path traversal / arbitrary file read-write | `open(`, `send_file`, `os.path.join(BASE, user)`, `tarfile.extractall`, `zipfile.extractall`, `shutil.copy` | Is the path built from a request param without normalisation? |
| SSRF | `requests.get`, `httpx`, `urllib.request.urlopen`, `aiohttp` with a user URL | Can a user control the fetched URL (webhook, "load from URL")? |
| SSTI / template injection | `Template(user).render`, `render_template_string`, f-strings into templates | Does user input reach the template *source*? |
| Command / arg injection | `subprocess`, `os.system`, `shell=True` | Does user input reach the argv/command? |
| Missing authz / IDOR | route handlers, `@app.route`/`@router` without an auth check; object lookups by raw id | Is there any authentication/ownership check on this endpoint? |
| Auth bypass | `==` on tokens, default creds, debug endpoints, `if not token:` gaps | Is the check constant-time / actually enforced? |

## First-target workflow (repeat until you find something real)
1. Confirm a candidate is **in-scope** on huntr.com/bounties; read its bounty terms.
2. `git clone` it locally; get it running in a throwaway VM/container **you own**.
3. First pass with tooling to build a shortlist of sinks:
   ```
   semgrep scan --config auto .
   bandit -r . -ll
   pip-audit            # sometimes the finding is a known-vuln dependency
   ```
4. **Manual review** of the flagged sinks — trace whether a request parameter,
   uploaded file, or config value actually reaches the sink. That trace is the bug.
5. Build a **minimal PoC** that demonstrates impact against your *local* instance
   only. Keep it minimal — enough to prove it, nothing weaponised.
6. Submit via huntr with clear repro steps + the PoC. The maintainer validates;
   if confirmed, you get the bounty and CVE.

## Safety / legal (non-negotiable)
- Test only software you downloaded and run **locally / in your own environment**.
- Never point a PoC at a third party's hosted service or another user's data.
- Follow huntr's disclosure process and any embargo. Coordinated disclosure only.
- Don't publish exploit details before the fix/advisory is out.

A clean disclosure record is part of the reputation you're building — sloppiness
here undoes the whole point.

## Evidence to capture (visa file)
huntr report link, CVE ID + advisory URL, maintainer acknowledgement, bounty
confirmation, and the disclosure timeline. These map straight to "recognised by
others" and "contribution beyond your day job."

## This week
1. Create the huntr account; read guidelines + pick **one** in-scope Python project.
2. Clone locally, run `semgrep --config auto` + `bandit -ll`, and write down the
   top 5 sinks worth a manual trace.
3. Trace one sink end-to-end. If it's exploitable, build the minimal PoC and submit.
