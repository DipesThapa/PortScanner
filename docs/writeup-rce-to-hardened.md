---
title: "Hardening my own Nmap web UI: the security holes I shipped, and what actually saved me"
published: false
tags: security, python, fastapi, appsec
canonical_url: ""
cover_image: ""
---

I built a web front end for an Nmap-based port scanner: a FastAPI backend, a React
dashboard, background scan jobs, a plugin system. It worked. Then I sat down and
audited it like an attacker would — and found a stack of real weaknesses, plus a
lesson in *why you verify an exploit before you call it one.*

This is the honest version: the holes I found, the unauthenticated-RCE chain I
*thought* I had, why it didn't actually fire, and the hardening I shipped anyway.

Repo: **https://github.com/DipesThapa/PortScanner**

> This is my own project, audited and fixed by me. No third-party systems were
> touched. Scanners are dual-use — only ever point one at hosts you own or are
> authorised to test.

## Hole 1: no authentication, anywhere

The foundation: **every** API route and the `/ws/status` WebSocket were open. No
API key, no session. The Dockerfile bound `0.0.0.0:8000` and ran as root. Anyone
who could reach the port could drive scans, hit the upload endpoint, and read
every job's logs.

```python
api_router = APIRouter()          # no dependencies — fully open
```

This is the real, unambiguous problem. Everything below is only interesting
*because* it sat behind no auth.

## Hole 2: an upload endpoint that allowlisted its own files

Deep-dive follow-up commands ran against an allowlist — good instinct. But an
upload endpoint wrote a file, `chmod +x`'d it, and then added it to that same
allowlist:

```python
for item in scripts_dir.glob("*"):
    if item.is_file():
        allowed.add(str(item.absolute()))   # upload authorises itself
```

An allowlist any input can extend isn't an allowlist. This is a genuine design
footgun.

## Hole 3: the RCE I *thought* I had — and why it didn't fire

Here's the chain I got excited about: the scan target flows toward Nmap's argv,
and it's `subprocess.run(..., shell=False)`. No shell injection — but you don't
need a shell to abuse Nmap. If a target became `--script=/uploaded.nse`, Nmap
would load and run that NSE (Lua) script, and NSE can call `os.execute`. Upload a
malicious `.nse` (Hole 2), get Nmap to load it (target-as-flag), done. Textbook
unauthenticated RCE.

Except when I actually tested it, **it didn't work** — and the reasons are the
interesting part:

1. **`argparse` blocks it.** The API doesn't call Nmap directly; it builds CLI
   args and passes them through the CLI's `argparse`. A flag-shaped value in the
   two-token form the API uses — `["--target", "--script=/evil.nse"]` — makes
   argparse error with *"expected one argument"*. The flag never reaches Nmap.

   ```python
   >>> p.parse_args(["--target", "--script=/tmp/evil.nse"])
   error: argument --target: expected one argument   # rejected
   ```

2. **A second gate blocks the upload path.** The deep-dive endpoint only runs
   commands that appear in the plugin's generated `available_cmds` (fixed
   templates for `nmap`/`nuclei`/`testssl.sh`). An uploaded script's path never
   lands in that set, so even though it's allowlisted, you can't invoke it.

So the "RCE" was **latent, not proven** — two accidental guardrails stood between
a genuinely bad design and actual code execution. That's worth saying plainly:
finding scary-looking primitives is easy; confirming they chain into a working
exploit is the actual work, and here they didn't.

## Hole 4: unsafe XML parsing (a real code smell)

Bandit flagged the Nmap-XML parser using `xml.etree.ElementTree.fromstring`
(B314) — vulnerable to XXE / entity expansion if the XML is untrusted. In the
normal scan flow Nmap generates and escapes its own XML, so it's hard to reach in
practice — but the moment you parse *user-supplied* XML (offline re-parsing, an
import feature), it's a real hole. Cheap to fix, so fix it.

## The hardening I shipped

Even though the RCE wasn't exploitable as-shipped, every weakness was worth
closing — secure-by-design beats "technically blocked by an accident":

- **Auth on everything.** `X-API-Key` dependency on the whole API router; the
  WebSocket validates a token. Key from `PORTSCANNER_API_KEY` or generated to
  `web_runs/.api_key` (0600) on first boot — never anonymous. Constant-time compare.
- **Input validation + defence in depth.** Targets must match a hostname/IP/CIDR
  pattern and can't start with `-`; dangerous flags (`--script`, `-oN`, …) are
  rejected; and a `--` sentinel goes before the target so Nmap stops parsing
  options regardless.
- **Uploads no longer self-authorise**, and upload is disabled unless an operator
  opts in with `PORTSCANNER_ENABLE_SCRIPT_UPLOAD=1`.
- **`defusedxml`** for all Nmap-XML parsing.
- Secret redaction before logs are persisted; non-root container with
  `cap_net_raw` scoped to the Nmap binary; pinned deps. Locked in with a
  `tests/test_security.py` suite and CI: pytest, Bandit, pip-audit, CodeQL.

## Five things worth stealing

1. **Auth is link zero.** Everything else only matters relative to "who can reach it."
2. **Verify the exploit before you name it.** A scary primitive isn't a
   vulnerability until you've walked it end to end. Mine died at `argparse`.
3. **`shell=False` ≠ safe** — the invoked program still parses its own args. Put
   `--` before positionals and validate anything flag-shaped anyway.
4. **An allowlist inputs can extend isn't one.** Don't let the thing being
   authorised share a writer with the authoriser.
5. **Run the scanners.** Bandit/CodeQL/pip-audit in CI caught the XML issue my
   manual review skimmed past.

Full before/after, threat model, and CI are in the repo. If I got something
wrong, open an issue — publishing the honest version is the whole point.

**https://github.com/DipesThapa/PortScanner**
