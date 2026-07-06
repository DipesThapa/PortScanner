# PR guide: submitting the `subprocess-argv-injection` Semgrep rule

You have a **verified, passing** Semgrep rule (`subprocess-argv-injection.yaml`)
plus its test file (`subprocess-argv-injection.py`). Semgrep's own harness
confirms all `# ruleid:` and `# ok:` cases behave correctly:

```
$ semgrep --test --config subprocess-argv-injection.yaml subprocess-argv-injection.py
1/1: ✓ All tests passed
```

It flags the vulnerable pattern (argv list with a user value, no `--` sentinel)
and does **not** flag code that adds `--` — the exact fix from the write-up.

## What this rule detects (CWE-88, argument injection)
A `subprocess` call whose argv list contains a non-literal element and no `"--"`
separator. Even with `shell=False`, the invoked program parses its own flags, so
a user-controlled value like `--script=/tmp/evil` becomes an option. This is a
class the existing registry rules (which focus on `shell=True` / formatted-string
command injection) don't cover.

## Step-by-step: open the PR

1. **Fork** `semgrep/semgrep-rules` on GitHub and clone your fork.
2. **Read** `CONTRIBUTING.md` in that repo (it documents rule layout, metadata
   requirements, and the `semgrep --test` workflow).
3. **Place the files** at the conventional path (rule + test share a stem):
   ```
   python/lang/security/audit/subprocess-argv-injection.yaml
   python/lang/security/audit/subprocess-argv-injection.py
   ```
   (Confirm the exact folder against neighbours like
   `python/lang/security/audit/`; match whatever the repo currently uses.)
4. **Set the rule id to match the path** — semgrep-rules requires the `id` to
   equal the dotted path, e.g.
   `python.lang.security.audit.subprocess-argv-injection`. Update the `id:` field
   accordingly before submitting (the local copy uses the short id for testing).
5. **Run the tests locally** from the repo root:
   ```
   semgrep --test --config python/lang/security/audit/subprocess-argv-injection.yaml \
     python/lang/security/audit/subprocess-argv-injection.py
   ```
   Expect `✓ All tests passed`.
6. **Open an issue first** (recommended): "Proposing an audit rule for argv
   argument injection (CWE-88) in subprocess calls" — briefly describe the gap
   vs. existing command-injection rules and link your write-up. Wait for a
   maintainer's thumbs-up.
7. **Open the PR.** Suggested description:

   > **Add `subprocess-argv-injection` (CWE-88, audit)**
   >
   > Adds a LOW-confidence audit rule for argument injection in `subprocess`
   > calls: an argv list containing a non-literal element with no `--` separator.
   > Even with `shell=False`, the invoked program parses its own arguments, so a
   > user-controlled value beginning with `-` is interpreted as an option (e.g. a
   > scan target `--script=/tmp/evil` becoming an nmap flag).
   >
   > Existing registry rules target `shell=True` and formatted-string command
   > injection; this covers the distinct argv/positional case. Marked `audit` /
   > LOW confidence to keep signal-to-noise appropriate. Suggested remediation: a
   > `--` sentinel before user-controlled positionals and rejecting leading-dash
   > values.
   >
   > Tests pass via `semgrep --test`. Background write-up: <your dev.to link>

## Honest expectations
Registry maintainers are selective, and an audit-tier heuristic may get feedback
(scope, false-positive concerns) before it merges — engage with it, that dialogue
*is* the contribution record. If they prefer not to take it, you still have:
- a **public, tested rule** in your own repo (add it to `.github/workflows/` or a
  `semgrep/` folder and mention it in the README), and
- the option to **publish it to the Semgrep Registry** under your account
  (semgrep.dev → Playground → Publish), which gives it a permanent URL with your
  name on it regardless.

Either way, you end up with a citable artifact. The merged upstream PR is the
bonus, not the only prize.
