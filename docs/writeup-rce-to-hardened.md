---
title: "I shipped an unauthenticated RCE in my own port scanner — here's the whole chain, and how I killed it"
published: false
tags: security, python, fastapi, appsec
canonical_url: ""
cover_image: ""
---

I built a web front end for an Nmap-based port scanner: a FastAPI backend, a React
dashboard, background scan jobs, a plugin system, the works. It ran fine. Then I
sat down and actually audited it like an attacker would — and the thing was a
textbook unauthenticated remote-code-execution box.

This is the full chain, why each link existed, and the exact fixes. Every bug
here is one you can ship in any tool that shells out to a subprocess, so the
lessons transfer well beyond this project.

Repo (hardened): **https://github.com/DipesThapa/PortScanner**

> Framing note: this is my own project, audited and fixed by me. No third-party
> systems were touched. Scanners are dual-use — only ever point one at hosts you
> own or are authorised to test.

## The stack in one breath

- `POST /api/scans` accepts a JSON body (target, ports, scripts, extra nmap args).
- A `JobManager` runs the scan in a background thread, shelling out to `nmap`.
- A "deep-dive" feature runs follow-up tools (`nmap`, `nuclei`, `testssl.sh`)
  against an allowlist.
- A React dashboard talks to the API and a `/ws/status` WebSocket.

Four features, four attack surfaces. Here's how they combined.

## Link 0: there was no authentication at all

The foundation of the whole chain: **every** route and the WebSocket were open.
No API key, no session, nothing. The Dockerfile bound `0.0.0.0:8000` and ran as
root. So everything below is reachable by anyone who can hit the port.

```python
app = FastAPI(...)
api_router = APIRouter()          # no dependencies
# ... every scan/upload/deepdive route hangs off this open router
```

If your service does anything more privileged than serve static files, "we'll
add auth later" is how you end up here. Auth is link zero.

## Link 1: Nmap argument injection (no shell required)

The scan target flowed from the JSON body straight into the Nmap argv:

```python
def build_nmap_command(target, start_port, end_port, ...):
    command = ["nmap", "--reason", "-p", port_range, "-oX", "-"]
    # ...flags...
    command.append(target)        # <-- attacker-controlled, last positional
    return command
```

It's `subprocess.run(command, shell=False)`, so there's no classic shell
injection. People stop worrying at that point. They shouldn't — **you don't need
a shell to abuse a tool as powerful as Nmap.** If `target` is
`--script=/path/to/evil.nse`, it's no longer a target; it's a flag. Nmap will
happily load and run that NSE (Lua) script. Nmap can also write files
(`-oN /etc/cron.d/x`), read files via scripts, and more. `extra_args` was passed
through verbatim too, so you didn't even need the trick.

`shell=False` protects you from the shell. It does nothing about the program
you're actually invoking interpreting its own arguments.

## Link 2: uploaded scripts that authorised themselves

The deep-dive runner executed only allowlisted commands — good instinct. But
there was an upload endpoint:

```python
async def save_script(self, name, content):
    script_path = scripts_dir / Path(name).name   # traversal handled, ok
    self._write_script(script_path, content)       # writes + chmod +x
    return str(script_path)

def _load_allowlist(self, initial):
    # ...
    for item in scripts_dir.glob("*"):
        if item.is_file():
            allowed.add(str(item.absolute()))       # <-- upload allowlists itself
```

Read those two together: an uploaded file is written, made executable, and then
**added to the very allowlist that's supposed to gate execution.** The allowlist
was checking a lock whose key it handed out for free. An allowlist that any input
can extend is not an allowlist.

## The chain

No auth (link 0) + write-an-executable-and-allowlist-it (link 2) + get Nmap to
load an arbitrary NSE file (link 1) = an unauthenticated network attacker runs
code on the host. Each piece looked defensible in isolation. Chained, it's game
over. That's the thing about appsec: bugs compose.

## The bonus one I didn't see coming: XXE

While wiring up CI I ran [Bandit](https://bandit.readthedocs.io/) and it flagged
the XML parser:

```python
import xml.etree.ElementTree as ET
root = ET.fromstring(xml_output)   # B314: untrusted XML
```

Nmap emits XML, and I parse it. But that XML describes *the host you scanned* —
which can be attacker-controlled. A hostile service can shape responses so the
resulting Nmap XML carries an XXE payload (`file:///etc/passwd`, entity
expansion, SSRF). The stdlib parser resolves external entities. Static analysis
caught a bug my manual review walked straight past.

## The fixes

**Authentication on everything.** An `X-API-Key` dependency on the whole API
router; the WebSocket validates a token. Key comes from `PORTSCANNER_API_KEY` or
is generated to `web_runs/.api_key` (0600) on first boot — never anonymous.
Constant-time comparison.

```python
api_router = APIRouter(dependencies=[Depends(require_api_key)])
```

**Validate input; refuse flag-shaped values.** Targets must match a hostname/IP/
CIDR pattern and cannot start with `-`. Dangerous flags (`--script`, `-oN`,
`--datadir`, …) are rejected in `extra_args`. And defence in depth: a `--`
sentinel before the target so Nmap stops parsing options.

```python
command.append("--")      # everything after this is a positional, never a flag
command.append(target)
```

**Stop uploads from self-authorising.** Uploaded scripts are no longer added to
the allowlist; an operator must add them explicitly via env. Upload is disabled
entirely unless `PORTSCANNER_ENABLE_SCRIPT_UPLOAD=1`.

**Kill the XXE with defusedxml.**

```python
from defusedxml.ElementTree import fromstring as _safe_fromstring
root = _safe_fromstring(xml_output)   # entities/DTDs refused
```

**The rest:** redact secrets (passwords, tokens, `secret://`) before logs hit the
DB; run the container as non-root with `cap_net_raw` scoped to the Nmap binary
only; pin dependencies. Then I locked it all in with a `tests/test_security.py`
suite (auth, injection, XXE, redaction) and CI: pytest, Bandit, pip-audit, and
CodeQL on every push.

## Five things worth stealing

1. **Auth is link zero.** Everything else is only as safe as "who can reach it."
2. **`shell=False` ≠ safe.** The invoked program parses its own args. Put `--`
   before positionals and validate anything flag-shaped.
3. **An allowlist that inputs can extend isn't one.** Authorisation and the data
   being authorised must not share a writer.
4. **Untrusted XML is untrusted even when *you* generate it** — if it's derived
   from something an attacker controls, parse it with `defusedxml`.
5. **Automated scanners see what tired eyes miss.** Bandit/CodeQL/pip-audit in CI
   caught a real bug I'd read past. Cheap, run them.

Full before/after is in the repo, including the [threat model](https://github.com/DipesThapa/PortScanner/blob/main/SECURITY.md)
and CI config. If you spot something I still got wrong, open an issue — that's
the point of publishing it.

**https://github.com/DipesThapa/PortScanner**
