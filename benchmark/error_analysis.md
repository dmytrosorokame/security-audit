# Benchmark error analysis — misclassifications & candidate fixes

_Companion to `results.md`. Records every misclassified case from the headline
run, its root cause, and a candidate fix — **without** applying any change._

## Provenance

- **Run:** `node benchmark/run_benchmark.mjs --seeds=3 --provider=openai --model=gpt-5 --min-f1-strict=0 --min-f1-loose=0`
- **Model:** `gpt-5` · **seeds:** 3 · **corpora:** 7 (87 cases, 261 calls)
- **Source of truth:** `results.md` generated `2026-06-07T22:26:19Z`
- **Headline:** F1 ranges from 1.000 (`snyk`) down to 0.714 (`oss_pilot`),
  with the lowest score on `oss_pilot` marking the generalisation
  boundary. Strict F1 == loose F1 on every corpus
  (when the model flags a vuln it pins the exact `rule_id`; the OWASP+CWE loose
  matcher never rescues a near-miss).

| Corpus | F1 (strict = loose) | Misclassifications |
|--------|--------------------|--------------------|
| expected (smoke) | 0.933 | 1 FN |
| independent | 0.947 | 1 FP |
| complex | 0.909 | 1 FN |
| nodegoat | 0.828 | 1 FN (+ 4 FP, see note) |
| juiceshop | 0.909 | 1 FN, 1 FP |
| snyk | 1.000 | — |
| oss_pilot | 0.714 | 2 FN, 2 FP |

> **Read the FP counts with Category D below in mind.** Of the 8 false positives
> in the confusion matrices across the suite, **5 are duplicate detections of
> the *correct* rule** (1 in independent, 4 in nodegoat) — scoring artefacts,
> not wrong findings. Only **3 FPs are genuine** (tn02 + the two `NEW_PATTERN`
> off-catalog warns). With rule-level de-duplication the genuine picture is
> independent F1 → 1.000 and nodegoat F1 → ~0.96 (computable below, no rerun).

## Method & honesty caveats

- Root causes were established by reading each case's **ground-truth diff +
  expected JSON** and comparing against the **actual catalog rule text**
  (`references/owasp-rules.md`). This pinpoints *whether the rule as written
  would even direct the model to the pattern*.
- **The per-run model outputs were not persisted** (the harness disables its
  file cache whenever `seeds > 1`, to measure variance against fresh calls, and
  `results.md` keeps only detected `rule_id`s). So for the **false positives**,
  the model's actual reasoning is **inferred** from the diff, not observed.
  Confirming it would require re-running those cases — explicitly out of scope.
- **Any catalog edit re-grounds every case** (the cache key hashes system
  prompt + catalog + mapping + few-shot). So acting on anything here means a
  fresh paid run. None of the proposals below have been applied or validated.
- **Generalisation caveat:** these fixes are derived *after seeing the test
  failures*. Enriching a rule to capture a pattern the benchmark exposed is
  legitimate domain knowledge — but it converts the affected corpora from
  held-out to tuned-against. Any post-hoc improvement **must be disclosed** as
  such in the report, and the pre-tuning numbers above remain the honest
  held-out baseline. We deliberately did **not** touch `prompts/few_shot.md`:
  adding examples that mirror benchmark cases is the memorisation that
  `few_shot.md` already warns inflates F1.

## Summary

| # | Case | Corpus | Type | Expected | Detected | Category |
|---|------|--------|------|----------|----------|----------|
| 1 | js10_ssti_userprofile | juiceshop | FN | B-15 | — | A · tractable rule gap |
| 2 | ng04_idor_allocations | nodegoat | FN | B-11 | — | A · tractable rule gap |
| 3 | c01_ssrf_via_extracted_helper | complex | FN | B-04 | — | A · tractable (cross-file) |
| 4 | 04_idor_ambiguous | expected | FN | B-11 | — | B · hard by design |
| 5 | op01_follow-redirects (CVE-2023-26159) | oss_pilot | FN | B-14/B-04 | — | B · hard by design |
| 6 | op06_ansi-regex (CVE-2021-3807) | oss_pilot | FN | B-18 | — | B · diff-only limit (library) |
| 7 | tn02_hardened_redirect | juiceshop | FP | — (TN) | B-14 | C · precision trade-off |
| 8 | form-data__form-data__pr4 | oss_pilot | FP | — (TN) | NEW_PATTERN | C · off-catalog over-warn |
| 9 | koajs__koa__pr1930 | oss_pilot | FP | — (TN) | NEW_PATTERN | C · off-catalog over-warn |

Verdicts use the **best of the 3 seeds** (the run with the most findings), so
every FN above is a *consistent* miss — the model's most detective run still
missed it — not a 1-of-3 fluke.

The 9 cases above are the genuine FN/FP misclassifications. Separately,
**Category D** below covers a scoring artefact that inflates the FP *count* on
two corpora without any wrong finding.

---

## Category D — Duplicate-detection scoring artefact (highest-impact, grounding-free)

**This is the single most impactful and most defensible correction, and it
needs no model rerun.**

`classify()` (in `run_benchmark.mjs`) matches **one** actual finding per expected
finding (a `used` index set) and counts **every remaining finding as an extra →
FP**. So when the model reports the *same correct rule more than once* on a case,
the duplicates are scored as false positives even though the detection is right.

Evidence — every multi-detection row in `results.md` (the model restating the
same `rule_id`):

| Case | Corpus | Expected | Detected (best run) | Extras counted as FP |
|------|--------|----------|---------------------|----------------------|
| i07_weak_crypto_password_hash | independent | B-07 | `B-07, B-07` | 1 |
| ng02_eval_injection_contributions | nodegoat | B-06 | `B-06, B-06, B-06` | 2 |
| ng11_missing_func_authz_benefits | nodegoat | B-19 | `B-19, B-19` | 1 |
| ng13_plaintext_password | nodegoat | B-21 | `B-21, B-21` | 1 |

That is **1 FP in independent and 4 FP in nodegoat — all 5 are duplicates of the
correct rule.** They account for *the entire* FP column on both corpora.

**Root cause.** Scoring treats each emitted finding as a distinct alert. Standard
SAST benchmarking treats a finding as *a vulnerability class at a location*, so
N restatements of the same `rule_id` on one case are one finding. The catalog
even instructs one-finding-per-issue, but nothing dedupes when the model repeats.

**Candidate fix (scoring only — does NOT change the grounding/cache key):**
de-duplicate `actualFindings` before `classify()`, keyed by `rule_id` (or, more
conservatively, `rule_id + line`), so duplicates collapse to one. This is a
`classify()`/harness change, not a prompt change — **no benchmark-gaming concern,
no re-grounding.**

**Impact (computed analytically from the duplicates above — no rerun):**

| Corpus | As-run | With rule-level dedup |
|--------|--------|------------------------|
| independent | 9 TP, 1 FP, 0 FN → P 0.900, F1 0.947 | 9 TP, 0 FP, 0 FN → **P 1.000, F1 1.000** |
| nodegoat | 12 TP, 4 FP, 1 FN → P 0.750, F1 0.828 | 12 TP, 0 FP, 1 FN → **P 1.000, F1 ~0.960** |

**Caveat on re-scoring the *current* run:** the fix applies cleanly to the next
run, but the existing run's raw per-finding outputs were not persisted
(`seeds > 1` disables the cache), so the table above is the analytic correction
rather than a re-scored artefact. A cheap, honest way to *bank* it without a paid
rerun would be to additionally persist raw findings on future runs and re-score
offline.

**Recommendation.** This is worth adopting regardless of the rule-coverage
debate: it is methodologically standard, changes no model input, and removes a
real downward bias in precision on two corpora. Report both the as-run and
dedup-corrected numbers.

---

## Category A — Tractable rule-coverage gaps

These are genuine gaps between the catalog text and a recognisable, generalisable
vulnerability shape. A rule-description enrichment (not a few-shot mirror) is the
sound fix.

### 1. js10_ssti_userprofile — B-15 SSTI (FN)

**Diff (the vulnerable side):**
```ts
let username = user.username
template = await fs.readFile('views/userProfile.pug', { encoding: 'utf-8' })
template = template.replace(/_username_/g, username)   // user input → template SOURCE
const fn = pug.compile(template)
res.send(fn(user))
```

**Root cause.** B-15's vulnerable examples and confidence guidance all key on
the template argument coming **directly** from `req.*`:
> "any template engine `compile`/`render`/`renderFile`/`renderString` with
> **first arg from `req.*`** is critical TP."

Here the first arg to `pug.compile` is a **local variable** (`template`) built by
string-substituting user input into template source one hop earlier. The taint
is `user.username → String.replace into template → compile(template)`. The rule
as written does not describe "user-controlled value concatenated/substituted
**into** template source before `compile()`", so it never directs the model to
this shape. Critical-severity miss.

**Candidate fix.** Add to B-15 a vulnerable variant and confidence line:
> Also TP: a user-controlled value substituted or concatenated **into** the
> template string before `compile`/`render` (`tpl = base.replace(/_x_/, userVal); pug.compile(tpl)`,
> `` pug.compile(`...${userVal}...`) ``). The danger is user data reaching the
> *template body*, even indirectly — not only `req.*` passed directly as the
> first argument.

**Risk.** Low. Generalisable; unlikely to introduce FPs (substituting user input
into template *source* is rarely legitimate).

### 2. ng04_idor_allocations — B-11 IDOR (FN)

**Diff (the vulnerable side):**
```js
this.displayAllocations = (req, res, next) => {
-   const { userId } = req.session;
+   const { userId } = req.params;     // identity now from the URL, not the session
    // ...userId used to read allocations...
```

**Root cause.** B-11's vulnerable pattern is "lookup *by* a user-supplied id
without an ownership check" (`Model.findById(req.params.id)`). ng04 is a
different shape: the **authorization identity itself** is re-sourced from
request input (`req.session.userId → req.params.userId`), dropping the binding
between the request and the authenticated user. The rule never describes "the
owner/user id used for the authz decision is read from `req.params|query|body`
instead of `req.session`/`req.user`", so the swap reads as ordinary parameter
handling.

**Candidate fix.** Add to B-11:
> Also TP: the **identity** used for an authorization or ownership decision is
> read from request input (`const { userId } = req.params|query|body`) rather
> than from the authenticated session (`req.session` / `req.user`). Re-sourcing
> the owner id from the URL lets any user act as any other.

**Risk.** Medium — must not fire when `req.params.id` is the *object* key that is
*then* ownership-checked against `req.user.id` (the legitimate pattern B-11
already calls safe). Wording must target the case where the request value
*replaces* the trusted identity, leaving no independent owner to check against.

### 3. c01_ssrf_via_extracted_helper — B-04 SSRF (FN)

**Diff (3 files):** `preview.ts` drops the `WHITELIST` and calls
`resolveTarget(req.query.target)`; new `utils/url.ts` defines
`resolveTarget` as `return /^https?:\/\//.test(target) ? target : null;`; the
test file is a red herring (still "rejects unknown targets", but "unknown" now
means "not URL-shaped", not "not in the allowlist").

**Root cause.** Two compounding factors:
1. **Cross-file taint** — the sink `axios.get(url)` is in `preview.ts` but the
   (non-)validation is in `utils/url.ts`. The model must connect them.
2. **B-04 does not flag format-only validation as insufficient.** Its guidance
   says "Allowlist-validated URLs are safe" but never warns that a **syntactic**
   `^https?://` check is *not* a host allowlist. `resolveTarget` returning `null`
   for malformed input reads like validation, so the model credits it as the
   safe pattern.

**Candidate fix.** Add to B-04:
> A URL that passes only **format/scheme validation** (`/^https?:\/\//`,
> `new URL(x)` succeeding, "is it a valid URL") is **not** mitigated — SSRF
> requires a **host allowlist** (or blocking private/loopback ranges). Treat a
> helper that merely confirms URL shape and returns the URL as an unguarded
> sink.

**Risk.** Medium. The cross-file hop is an inherent diff-only difficulty the
rule edit cannot remove; the fix only helps if the model already connected the
files. Partial expected lift.

---

## Category B — Hard by design (honest diff-only / capability limits)

These are not rule-text defects. They reflect the diff-only architecture's
genuine limits and should be reported **as limitations**, not "fixed."

### 4. 04_idor_ambiguous — B-11 (FN)

IDOR **by omission**: a new `POST /profile/:id/avatar` route mutates any profile
without an ownership check. The case's own notes state: *"NEEDS_HUMAN verdict is
acceptable because the auth middleware that might sit upstream is not visible in
the diff."* The model cannot know whether `requireOwnership` middleware guards
the route elsewhere. Forcing a TP here would trade recall for precision on every
legitimately-guarded new route. **Leave as a documented diff-only limit.**

### 5. op01_follow-redirects CVE-2023-26159 — B-14/B-04 (FN)

The vulnerable diff **adds** a `try/catch` and an `InvalidUrlError` throw — it
superficially looks like *hardening*. The actual flaw is semantic: on
`new URL()` failure it falls back to the permissive legacy `url.parse()`,
enabling hostname confusion. There is no `res.redirect`/outbound-call sink in
the diff (it is parser-internal library code), so neither B-14 nor B-04's sink
patterns apply. Detecting this requires knowing the security difference between
`new URL()` and `url.parse()` and recognising a vuln that *looks* like a fix.
**Genuine capability limit; very low ROI to chase.**

### 6. op06_ansi-regex CVE-2021-3807 — B-18 ReDoS (FN)

The diff reverts ansi-regex to the ambiguous `[a-zA-Z\d]*(?:;...)*`
overlapping-quantifier form — real catastrophic backtracking. Notably, **the
model followed the rule correctly**: B-18 requires a *visible user-input source*
and explicitly says a "compile-time constant tested only against bounded,
non-user data" is FP and "NEEDS_HUMAN when the input source is not visible in
the diff." op06 is **library-internal** code: the regex is a module constant and
the matched string comes from whatever downstream caller uses ansi-regex —
invisible in the diff. Relaxing B-18 to fire on constant regexes with no visible
input would make it flag every internal regex (precision collapse).

This is an honest and slightly uncomfortable finding worth highlighting: **even a
rule purpose-built during benchmarking (B-18) cannot catch a real ReDoS CVE when
the threat depends on caller context the diff doesn't show.** It is a property of
the diff-only unit of analysis, not a fixable rule defect.

---

## Category C — Precision trade-offs (false positives)

> Model outputs were not persisted; the flagged `rule_id` is known but the
> reasoning is **inferred** from the diff. Confirming requires a re-run.

### 7. tn02_hardened_redirect — flagged B-14 on a TN (FP)

**Diff:** `const isAllowed = security.redirectAllowlist.some(a => a === toUrl || toUrl.startsWith(a + '?')); if (isAllowed) res.redirect(toUrl)`.
This is a correct exact-match allowlist (the `startsWith(a + '?')` branch is
anchored to a known-good prefix plus query string).

**Inferred root cause.** B-14's confidence guidance is blunt — "`res.redirect(req.X)`
is TP" — and its *safe* examples use `ALLOW.has(next)` (Set membership). The
model likely (a) saw `res.redirect(toUrl)` with `toUrl` from `query.to` and
fired, not crediting the `.some(a => a === toUrl ...)` **array** exact-match as
equivalent to the Set form, and/or (b) read the `startsWith(...)` branch as the
unsafe substring pattern.

**Candidate fix.** Broaden B-14's "safe" recognition: an array `.some(a => a === target)`
exact-match (with an anchored `startsWith(a + '?')` for query strings) is
equivalent to a `Set.has()` allowlist and is safe.

**Risk.** **High — this is the dangerous one.** js09 (the vulnerable counterpart)
uses a substring `includes()` check and *must still* be flagged. Any wording
that excuses `startsWith` risks suppressing js09. Needs careful validation
against both cases before adoption.

### 8 & 9. form-data PR#4 and koajs PR#1930 — flagged NEW_PATTERN on TNs (FP)

Both are real-world **benign** PRs labelled TN, both flagged with an
**off-catalog** finding (`rule_id: NEW_PATTERN`):
- **form-data #4** adds `getCustomHeaders(contentType)` / `getLengthSync()`
  helpers. Plausible trigger: `'content-type': contentType + '; boundary='` —
  the model may have read the caller-supplied `contentType` concatenated into a
  header as header injection. Annotator: benign new convenience API, no taint or
  guard change.
- **koajs #1930** adds a `workflow_dispatch` trigger to the npm-publish CI
  workflow. Plausible trigger: the model may have read a manually-dispatchable
  publish workflow with a tag input as an untrusted-checkout / CI-injection
  risk. Annotator: the ref is a *maintainer*-supplied input on a privileged
  workflow, not external PR input — no regression.

**Inferred root cause.** Both are the tool **over-warning on novel code outside
the catalog** — emitting a speculative finding rather than staying silent. This
is exactly the realistic-noise precision cost that only `oss_pilot` (no few-shot
overlap, real PRs) exposes, and it is **valuable honest signal**, not obviously a
defect to suppress.

**Candidate directions (each with a real downside):**
- *Scoring stance:* decide whether `NEW_PATTERN` (off-catalog) findings should
  count against catalog precision at all. Excluding them is defensible (the
  benchmark measures the catalog) but risks looking like moving the goalposts.
- *Prompt discipline:* instruct the model to emit only catalog rules, or to
  raise the confidence bar before reporting off-catalog patterns. Risks
  suppressing legitimate findings the catalog doesn't yet cover.

**Recommendation:** keep as reported. These FPs are the most informative data
point about real-world precision and should be discussed, not engineered away.

---

## If these were ever actioned — validation protocol

To keep the science honest, any subset of the Category-A fixes would require:

1. Edit **only** `references/owasp-rules.md` (never `few_shot.md`).
2. Iterate cheaply at `seeds=1` (cache **on**) against just the affected corpora
   — juiceshop for B-15, nodegoat + expected for B-11, complex for B-04 — to
   confirm the target case flips to TP **and** check for new FPs (especially
   js09 / the safe IDOR/redirect counterparts).
3. One final full `seeds=3` run (~$7) to produce comparable headline numbers.
4. Report **both** the pre-tuning held-out F1 (the honest baseline in
   `results.md`) and the post-tuning F1, labelling the latter as
   benchmark-informed.

Expected realistic lift, stated **on top of the Category-D dedup correction**
(independent → 1.000, nodegoat → ~0.96): a successful Category-A fix adds ~1 TP
each — juiceshop (B-15) → ~0.95, nodegoat (B-11, clears its last FN) → ~1.0,
complex (B-04, cross-file caveat) → ~0.93. `oss_pilot` is dominated by
Category-B/C cases and would likely stay near 0.71. The Category-B and -C cases
should remain as documented limitations.

**Priority order if actioning anything:** (D) dedup — free, standard, no rerun;
then (A) B-15 and B-11 rule enrichment — generalisable, disclose as
benchmark-informed; leave (B) and (C) as honest limitations.
