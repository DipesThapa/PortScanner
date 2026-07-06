# Go-live checklist — turning the repo into recognised impact

Work top to bottom. Steps 1–4 make the repo credible; 5–7 drive the traffic that
becomes stars, discussion, and (for the visa) evidence of peer recognition.

## 1. Make the repo look maintained (before anyone visits)
- [ ] Push the hardening commit (`git push origin main`).
- [ ] Watch the **Actions** tab — CI + CodeQL should run green. Green badges in
      the README are a credibility signal; a failing badge is worse than none.
- [ ] Set the repo **About**:
  - Description: `Authenticated FastAPI + React platform over Nmap — scanning, plugins, baselining. Hardened: auth, input validation, XXE-safe parsing, CI/CodeQL.`
  - Website: the published article URL (once live).
  - Topics: `security` `appsec` `nmap` `port-scanner` `fastapi` `python` `react` `devsecops` `vulnerability-scanner` `docker`
- [ ] Upload a **social preview image** (Settings → General → Social preview) —
      the architecture diagram or a clean screenshot. This is what renders when
      the link is shared on LinkedIn/HN/Reddit.
- [ ] Enable **Issues** and **Discussions** (so people can engage = signal).

## 2. Pin the story where visitors land
- [ ] The README already leads with the architecture + threat model. Add a one-line
      link near the top to the writeup once published.
- [ ] Add a 20–40s screen-capture GIF of the dashboard to the README (record with
      QuickTime/Kap). Do **not** host a public live instance of a scanner.

## 3. Publish the writeup (centrepiece)
- [ ] `docs/writeup-rce-to-hardened.md` → paste into **dev.to** (or Hashnode).
      Front matter tags are already set. Add a cover image (the diagram).
- [ ] Set the dev.to canonical URL to itself; if you also cross-post to Hashnode,
      point Hashnode's canonical at the dev.to URL (avoids SEO duplicate penalty).
- [ ] Put the final article URL back into the repo About + README.

## 4. License + contribution basics
- [ ] `LICENSE` (MIT) is in place — GitHub will now show "MIT" in the sidebar.
- [ ] (Optional) Add `CONTRIBUTING.md` and a `.dockerignore`.

## 5. Launch posts (order matters — article first, then socials point to it)
- [ ] **dev.to/Hashnode** — publish. This is the canonical link everything else uses.
- [ ] **Hacker News** — `docs/launch/hacker-news.md` (Show HN + first comment).
- [ ] **r/netsec** — `docs/launch/reddit-netsec.md` (article link, technical title).
      Have the r/Python / r/selfhosted fallbacks ready if it's removed.
- [ ] **LinkedIn** — post the narrative version and tag it to your professional
      profile (this is the one that most directly supports the visa file).

## 6. Sustain (this is what recognition actually looks like)
- [ ] Reply to every comment/issue within a day. Engagement compounds.
- [ ] Convert 2–3 pieces of real feedback into follow-up commits — a public record
      of iteration reads as competence.
- [ ] Contribute one PR to a *well-known* OSS security project. A merged PR
      elsewhere is stronger visa evidence than your own repo.
- [ ] If someone references/links the repo or writeup, **screenshot and save it** —
      that's your "recognised by others" evidence for the endorsement.

## 7. Capture evidence as you go (for the Global Talent file)
Keep a folder of: the published article + view/reaction counts, HN/Reddit threads,
stars/forks over time, any external links or mentions, and merged PRs elsewhere.
These are the artefacts that back the "recognition" and "contribution" criteria.

---

### Honest expectations
Most launches are quiet. One good thread or a few engaged issues is a genuine win
and is usable evidence. The compounding move is consistency: publish, engage,
iterate, contribute elsewhere — repeat. The repo is the anchor, not the whole case.
