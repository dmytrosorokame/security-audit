# Juice Shop corpus

External-validity corpus reconstructed from **OWASP Juice Shop**
(https://github.com/juice-shop/juice-shop). Each challenge maps to an OWASP
category and a code location.

## How cases are built
For each selected challenge, build a minimal diff that introduces that vuln into
the relevant file (e.g. re-introduce the SQLi in the login route, remove a
redirect allowlist), unified-diff under `diffs/`, labelled in `expected/`.

## Coverage-driven selection (spec §3.1)
Select by what the app contains, not by catalog fit. Add catalog rules for
uncovered classes rather than skipping cases.

## Provenance is mandatory
Same `provenance` block as the NodeGoat corpus README.

## Validate before benchmarking
`node scripts/validate_corpus.mjs benchmark/juiceshop_corpus`

## Case inventory (11 vuln + 2 TN controls)
The `+` side of each vuln diff is verbatim-real Juice Shop `master` code; the `-`
(safe) side is **reconstructed**, because Juice Shop ships the vulnerable code live
with no in-repo fix. Every vuln case is therefore `provenance.kind: "synthesized"`
(real vulnerable side, reconstructed safe baseline). The two TN controls are safe on
both sides and measure false-positive rate.

| id | class | Juice Shop file | rule | OWASP · CWE · sev |
|----|-------|-----------------|------|-------------------|
| js01 | SQL injection (login auth-bypass) | routes/login.ts | B-01 | A05 · CWE-89 · critical |
| js02 | NoSQL injection (`$where`) | routes/trackOrder.ts | B-03 | A05 · CWE-943 · high |
| js03 | Weak crypto (unsalted MD5) | lib/insecurity.ts | B-07 | A04 · CWE-327 · high |
| js04 | SSRF (fetch user imageUrl) | routes/profileImageUrlUpload.ts | B-04 | A01 · CWE-918 · high |
| js05 | XXE (`noent:true`) | routes/fileUpload.ts | B-12 | A02 · CWE-611 · high |
| js06 | Path traversal (zip-slip) | routes/fileUpload.ts | B-05 | A01 · CWE-22 · high |
| js07 | Unsafe eval / RCE (`vm.runInContext`) | routes/b2bOrder.ts | B-06 | A08 · CWE-502 · critical |
| js08 | IDOR (basket by id) | routes/basket.ts | B-11 | A01 · CWE-639 · high |
| js09 | Open redirect (substring allowlist) | routes/redirect.ts | B-14 | A01 · CWE-601 · medium |
| js10 | SSTI + eval (username → Pug) | routes/userProfile.ts | B-15 | A05 · CWE-94 · critical |
| js11 | JWT verify without algorithm allowlist | lib/insecurity.ts | B-22 | A04 · CWE-347 · high |
| tn01 | TN control: parameterised login query (safe) | routes/login.ts | — | `expect_zero_findings` |
| tn02 | TN control: hardened redirect allowlist (safe) | routes/redirect.ts | — | `expect_zero_findings` |

All 11 vuln cases are `synthesized`. **B-22** (JWT verification without an algorithm
allowlist, CWE-347) was added to `references/owasp-rules.md` by this plan to cover
the one Juice Shop class the catalog did not previously detect (coverage-driven,
spec §3.1/§6). js11 accepts B-07 as an alternative; js02 accepts B-01.

The two TN controls present correctly-secured code at known hotspots (a parameterised
login query; an exact/anchored redirect allowlist) so a finding on tn01/tn02 at
benchmark time would be a genuine false-positive signal worth reporting.
