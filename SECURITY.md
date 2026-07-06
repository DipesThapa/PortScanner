# Security

## Authorized use only

This is an active network reconnaissance and vulnerability-scanning tool. Only
scan systems you own or have **explicit written permission** to test.
Unauthorized scanning may be illegal in your jurisdiction.

## Authentication

Every `/api/*` route and the `/ws/status` WebSocket require an API key.

- Set `PORTSCANNER_API_KEY` (16+ characters) before starting the server.
- If unset, a strong random key is generated on first boot and written to
  `web_runs/.api_key` (mode `0600`). It is also printed to the server log once.
- Clients send the key as the `X-API-Key` header. The WebSocket also accepts it
  as a `?token=` query parameter.
- `GET /api/health` is intentionally unauthenticated for container health checks.

## Hardening applied

- **No anonymous access.** The API is never reachable without a valid key.
- **Target / argument validation.** Scan targets, ports, scripts, and extra nmap
  arguments are strictly validated. Flag-like targets and dangerous nmap flags
  (`--script`, `-oN`, `--datadir`, …) are rejected, and a `--` sentinel
  terminates nmap option parsing before the target as defense in depth.
- **Deep-dive execution** runs with `shell=False` against an explicit allowlist.
  Uploaded scripts no longer auto-authorize themselves; an operator must add them
  via `DEEP_DIVE_ALLOWLIST` / `DEEP_DIVE_ALLOWLIST_FILE`.
- **Script upload is disabled by default.** Enable only if you understand the
  risk: `PORTSCANNER_ENABLE_SCRIPT_UPLOAD=1`.
- **Log redaction.** Passwords, tokens, API keys, and `secret://` references are
  redacted before scan logs are persisted to the database.
- **Container** runs as a non-root user; `cap_net_raw` is granted to the nmap
  binary only, so raw scans work without running the service as root.

## Environment variables

| Variable | Purpose | Default |
|----------|---------|---------|
| `PORTSCANNER_API_KEY` | Required API key | auto-generated to `web_runs/.api_key` |
| `PORTSCANNER_ENABLE_SCRIPT_UPLOAD` | Allow `POST /api/plugins/scripts` | disabled |
| `PORTSCANNER_SAFE_CONFIG` | Path to safe scan config | `<project>/config_safe.json` |
| `DEEP_DIVE_ALLOWLIST` | Comma list / file of allowed deep-dive commands | `testssl.sh,nmap,nuclei` |
| `DEEP_DIVE_ALLOWLIST_FILE` | JSON/text file of allowed commands | – |
| `DEEP_DIVE_ALLOW_ALL` | Set `1` to disable allowlist enforcement (unsafe) | disabled |

## Deployment notes

Do not expose this service directly to untrusted networks. Terminate TLS at a
reverse proxy, restrict source IPs, and rotate `PORTSCANNER_API_KEY` regularly.

## Reporting

Report vulnerabilities privately to the maintainer rather than opening a public
issue.
