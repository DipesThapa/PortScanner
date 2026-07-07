# How to open the semgrep-rules PR (ml deserialization)

**Status:** verified. `semgrep --test` → `4/4 ✓`. Due-diligence done:
- No existing `torch.load` / `joblib.load` / `pandas.read_pickle` /
  `numpy allow_pickle` rule in the registry (confirmed via code search).
- `dill` is **already** covered by `avoid-dill`, so it's intentionally excluded.
- Rule matches the repo's conventions: per-library `avoid-*` ids, their metadata
  format (owasp 2017/2021/2025, cwe2021/2022-top25 flags), and a `pattern-not`
  that skips constant-string args to reduce false positives.

**Target location in semgrep-rules:**
`python/lang/security/deserialization/ml-deserialization.{yaml,py}`
(base branch: **develop**)

## Fastest path — git (recommended, reliable)

Run in your terminal (needs your GitHub login / `gh`):

```bash
# 1. Fork on GitHub first (button on github.com/semgrep/semgrep-rules), then:
git clone https://github.com/DipesThapa/semgrep-rules.git
cd semgrep-rules
git checkout develop
git checkout -b add-ml-deserialization-rules

# 2. Copy the two verified files in from your PortScanner repo:
cp /path/to/PortScanner-main/docs/growth/contrib/ml-deserialization.yaml \
   python/lang/security/deserialization/ml-deserialization.yaml
cp /path/to/PortScanner-main/docs/growth/contrib/ml-deserialization.py \
   python/lang/security/deserialization/ml-deserialization.py

# 3. (optional but good) verify locally:
semgrep --test --config python/lang/security/deserialization/ml-deserialization.yaml \
   python/lang/security/deserialization/ml-deserialization.py

git add python/lang/security/deserialization/ml-deserialization.*
git commit -m "Add ML deserialization rules (torch.load, joblib, pandas.read_pickle, numpy allow_pickle) - CWE-502"
git push -u origin add-ml-deserialization-rules

# 4. Open the PR from your branch -> semgrep:develop
gh pr create --repo semgrep/semgrep-rules --base develop \
  --title "Add ML deserialization rules (torch.load / joblib / pandas / numpy) - CWE-502" \
  --body "See below."
```

## PR description (paste this)

> Adds `python/lang/security/deserialization/ml-deserialization.yaml` with four
> audit rules for pickle-backed ML deserialisers that aren't currently covered:
>
> - `avoid-torch-load-untrusted` - `torch.load()` without `weights_only=True`
> - `avoid-joblib-load` - `joblib.load()`
> - `avoid-pandas-read-pickle` - `pandas.read_pickle()` / `pd.read_pickle()`
> - `avoid-numpy-allow-pickle` - `numpy.load(..., allow_pickle=True)`
>
> These are the model-file attack surface (CWE-502) behind many recent AI/ML
> CVEs. `dill` is already covered by `avoid-dill`, so it's excluded. Rules follow
> the existing deserialization conventions (metadata, `avoid-*` ids, constant-
> string `pattern-not` to reduce false positives). Tests pass via `semgrep --test`
> (`4/4`). Resolves #3990.

Tip: reference the issue (`Resolves #3990`) so the PR links back to your proposal.
