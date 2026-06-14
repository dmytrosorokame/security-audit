# NodeGoat corpus

External-validity corpus reconstructed from **OWASP NodeGoat**
(https://github.com/OWASP/NodeGoat), an intentionally insecure Express app whose
tutorial maps each OWASP Top 10 item to specific vulnerable code and its fix.

## How cases are built
For each selected vulnerability, take the documented **fix** commit and build the
**inverse** diff (fix reversed = the vuln-introducing change), in unified-diff
format under `diffs/`. Label it in `expected/<id>.json` per the schema in
`docs/superpowers/plans/2026-06-07-corpus-infrastructure.md`.

## Coverage-driven selection (spec §3.1)
Select cases by what NodeGoat actually contains, NOT by what the catalog already
covers. If a real vuln class is missing from `references/owasp-rules.md`, ADD a
catalog rule (with drift-check + tests) rather than skipping the case.

## Provenance is mandatory
Every `expected/*.json` MUST carry a `provenance` block:
`{ "kind": "real"|"synthesized", "source": "<commit URL / challenge id>", "note": "<how built>" }`.

## Validate before benchmarking
`node scripts/validate_corpus.mjs benchmark/nodegoat_corpus`

## Case inventory (13 cases)
All cases are vuln-introducing diffs reconstructed from NodeGoat `master`; the `+`
side is the vulnerable form, the `-` side the safe form. Provenance is `real` when
both sides are verbatim NodeGoat source (the live vulnerable code plus a documented
commented-out fix), and `synthesized` when NodeGoat ships no committed fix for that
spot and the safe baseline had to be reconstructed (vulnerable side still real).

| id | class | NodeGoat file | rule | OWASP · CWE · sev | provenance |
|----|-------|---------------|------|-------------------|------------|
| ng01 | NoSQL injection (`$where`) | app/data/allocations-dao.js | B-03 | A05 · CWE-943 · high | real |
| ng02 | Server-side JS injection (`eval`) | app/routes/contributions.js | B-06 | A08 · CWE-502 · critical | real |
| ng03 | SSRF (`needle.get`) | app/routes/research.js | B-04 | A01 · CWE-918 · high | synthesized |
| ng04 | IDOR (URL-supplied userId) | app/routes/allocations.js | B-11 | A01 · CWE-639 · high | real |
| ng05 | Missing CSRF protection | server.js | B-08 | A01 · CWE-352 · medium | real |
| ng06 | Open redirect (`/learn`) | app/routes/index.js | B-14 | A01 · CWE-601 · medium | real |
| ng07 | `javascript:` URL XSS in href | app/views/profile.html | R-04 | A05 · CWE-79 · high | synthesized |
| ng08 | Missing Helmet headers | server.js | B-09 | A02 · CWE-693 · medium | real |
| ng09 | Mass assignment (memos) | app/routes/memos.js | B-13 | A08 · CWE-915 · high | synthesized |
| ng10 | ReDoS (nested quantifier) | app/routes/profile.js | B-18 | A02 · CWE-1333 · medium | real |
| ng11 | Missing function-level authz | app/routes/index.js | B-19 | A01 · CWE-862 · high | real |
| ng12 | Insecure cookie/session flags | server.js | B-20 | A02 · CWE-1004 · medium | synthesized |
| ng13 | Plaintext password storage | app/data/user-dao.js | B-21 | A04 · CWE-256 · high | real |

9 cases are `real`, 4 (`ng03`, `ng07`, `ng09`, `ng12`) are `synthesized` (real
vulnerable side, reconstructed safe baseline — disclosed in each case's
`provenance.note`).
B-18..B-21 are catalog rules added by this plan to cover NodeGoat classes the
catalog did not previously detect (coverage-driven, spec §3.1/§6).

## Intentional exclusion — A9 vulnerable dependencies
NodeGoat's "A9 — Using Components with Known Vulnerabilities" is **out of scope for
this corpus**: outdated dependencies are detected by the dependency CVE scanner, not
the LLM diff analyzer, and a `package.json` version-pin diff does not exercise
diff-SAST. No TN control diffs are included here — true-negative controls live in the
Juice Shop corpus and the presumed-TN `oss_pilot` baseline.
