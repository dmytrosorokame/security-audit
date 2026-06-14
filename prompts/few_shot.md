# Few-shot examples for security-audit diff analysis

Below are 10 example diffs and the expected JSON output. They cover:
- (1) clear vulnerability introduction — `TRUE_POSITIVE`, full 3-element trace
- (2) refactor that introduces SSRF — `TRUE_POSITIVE` with explicit guard removal in trace
- (3) safe refactor — no findings
- (4) ambiguous IDOR — `NEEDS_HUMAN`, trace gap is highlighted
- (5) sanitizer removal regression — `TRUE_POSITIVE`, trace cites the deleted guard
- (6) self-critique downgrade — initial finding looks dangerous, but a guard found in the same hunk forces `FALSE_POSITIVE`
- (7) prototype pollution — `TRUE_POSITIVE`, distinguishing R-05 (client) from B-05 (server) by file path / context
- (8) repository-pattern refactor — `TRUE_NEGATIVE`, illustrates that safe abstractions over raw SQL are not B-01
- (9) NoSQL injection via `$where` — `TRUE_POSITIVE` distinguishing B-03 from B-01 by operator surface
- (10) sanitizer-shaped API relaxation (`DOMPurify.sanitize` called but `ADD_TAGS:['script']` defeats it) — `TRUE_POSITIVE`, shows config-change-as-relaxation pattern (R-01)

> **Honest disclosure of train/test leakage** — read this before citing any F1 number from `benchmark/results.md`:
>
> The following few-shot examples are structurally close to benchmark cases. This grounds the model on canonical catalog patterns by design, but it also means F1 on those corpora is inflated by memorisation rather than measuring generalisation:
>
> | Few-shot | Structurally similar benchmark case | Corpus | Overlap shape |
> |---|---|---|---|
> | Example 1 (DOM XSS via `innerHTML`) | `01_dom_xss_introduction` | smoke | identical pattern |
> | Example 4 (ambiguous IDOR) | `04_idor_ambiguous` | smoke | identical pattern |
> | Example 5 (DOMPurify removed) | `05_sanitizer_removed` | smoke | identical pattern |
> | Example 7 (prototype pollution via `setDeep`) | `i01_prototype_pollution_argv_merge` | **independent** | same file path / function name |
> | Example 8 (repository-pattern allowlist) | `c06_safe_large_refactor` | complex | same allowlist-constant pattern |
> | Example 9 (NoSQL `$where` injection) | `i09_nosql_injection_mongoose_where` | **independent** | same file path + same expected JSON spelled out |
> | Example 10 (DOMPurify `ADD_TAGS:['script']`) | `c02_compositional_xss_regression` | complex | same sanitizer-shape relaxation pattern |
>
> Implications for reading the results:
> - **Smoke F1 (0.933)** is an upper bound, not a generalisability claim.
> - **"Independent" F1 (0.947)** is partly a memorisation test, not a clean held-out measurement — at least i01 and i09 overlap with few-shot Examples 7 and 9. The genuinely held-out subset is ~8 cases, not 10.
> - **Complex F1 (0.909)** is closer to a fair measure but also leaks via Examples 8 and 10.
> - The only corpus with no few-shot overlap is **OSS pilot** (TN-only). Its precision = 0/4 on emitted findings is the honest external-validity number.
>
> See `docs/INDEPENDENT_VALIDATION.md` (Stage 2 plan with raw CVE-fix corpus + Cohen's κ from a second annotator) for the work that would actually close this gap. The cross-corpus methodology in `benchmark/results.md` is the project's current accountability mechanism for this bias.

These are injected into the LLM prompt so the model has concrete grounding for tone, structure, verdict discipline, and the **exploit_trace** discipline.

---

## Example 1 — Clear DOM XSS introduction (R-02)

**Input diff**:

```diff
diff --git a/apps/web/src/components/Comment.tsx b/apps/web/src/components/Comment.tsx
index 1a2b3c4..5d6e7f8 100644
--- a/apps/web/src/components/Comment.tsx
+++ b/apps/web/src/components/Comment.tsx
@@ -10,7 +10,8 @@ export function Comment({ comment }: { comment: { author: string; body: string }
   return (
     <article>
       <h3>{comment.author}</h3>
-      <p>{comment.body}</p>
+      <p ref={(el) => el && (el.innerHTML = comment.body)} />
     </article>
   );
 }
```

**Expected output**:

```json
{
  "schema_version": "1.0",
  "findings": [
    {
      "rule_id": "R-02",
      "owasp_id": "A05",
      "cwe_id": "CWE-79",
      "severity": "high",
      "confidence": "high",
      "verdict": "TRUE_POSITIVE",
      "file": "apps/web/src/components/Comment.tsx",
      "line": 13,
      "evidence": "<p ref={(el) => el && (el.innerHTML = comment.body)} />",
      "exploit_trace": [
        "source: comment.body — user-supplied per the Props type signature in the surrounding context",
        "sink: el.innerHTML = comment.body (line 13)",
        "missing guard: no sanitiser between the assignment and the source; the previous JSX text node, which auto-escaped, was deleted"
      ],
      "rationale": "The change replaces safe React text rendering with direct `innerHTML` assignment from user-supplied `comment.body`. Any HTML in a comment will execute as code in the user's browser.",
      "remediation": "Revert to JSX text interpolation (`<p>{comment.body}</p>`) which auto-escapes, or sanitize with DOMPurify: `el.innerHTML = DOMPurify.sanitize(comment.body)`. See https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
      "title": "DOM XSS via innerHTML with user-supplied comment body"
    }
  ],
  "summary": {
    "total": 1,
    "by_severity": { "critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0 },
    "by_owasp": { "A05": 1 }
  },
  "non_security_observations": []
}
```

---

## Example 2 — Refactor introduces SSRF (B-04)

**Input diff**:

```diff
diff --git a/api/src/services/preview.ts b/api/src/services/preview.ts
index 1111..2222 100644
--- a/api/src/services/preview.ts
+++ b/api/src/services/preview.ts
@@ -5,8 +5,8 @@ import axios from 'axios';

 export async function fetchPreview(req: Request, res: Response) {
-  const url = WHITELIST[req.query.target as string];
-  if (!url) return res.status(400).end();
+  const url = req.query.target as string;
   const r = await axios.get(url);
   res.json({ html: r.data });
 }
```

**Expected output**:

```json
{
  "schema_version": "1.0",
  "findings": [
    {
      "rule_id": "B-04",
      "owasp_id": "A01",
      "cwe_id": "CWE-918",
      "severity": "high",
      "confidence": "high",
      "verdict": "TRUE_POSITIVE",
      "file": "api/src/services/preview.ts",
      "line": 8,
      "evidence": "const url = req.query.target as string;\n   const r = await axios.get(url);",
      "exploit_trace": [
        "source: req.query.target — attacker-controlled HTTP query parameter",
        "sink: axios.get(url) — server issues an outbound HTTP request",
        "missing guard: the WHITELIST lookup and early-return were deleted in this same hunk; nothing remains to constrain the URL"
      ],
      "rationale": "The diff removes an allowlist (`WHITELIST[req.query.target]`) and passes `req.query.target` directly to `axios.get`. An attacker can now make the server fetch arbitrary internal URLs (cloud metadata, RDS, internal admin panels).",
      "remediation": "Restore the allowlist of permitted target URLs, or validate `req.query.target` against a strict pattern (e.g., scheme=https, host in {allowed_hosts}). See https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
      "title": "SSRF — allowlist removed, user-controlled URL passed to axios.get"
    }
  ],
  "summary": {
    "total": 1,
    "by_severity": { "critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0 },
    "by_owasp": { "A01": 1 }
  },
  "non_security_observations": []
}
```

---

## Example 3 — Safe refactor (no findings)

**Input diff**:

```diff
diff --git a/api/src/utils/format.ts b/api/src/utils/format.ts
--- a/api/src/utils/format.ts
+++ b/api/src/utils/format.ts
@@ -1,5 +1,7 @@
-export function formatDate(d: Date): string {
-  return d.toISOString().split('T')[0];
+export function formatDate(d: Date, locale = 'en-US'): string {
+  return new Intl.DateTimeFormat(locale, {
+    year: 'numeric', month: '2-digit', day: '2-digit',
+  }).format(d);
 }
```

**Expected output**:

```json
{
  "schema_version": "1.0",
  "findings": [],
  "summary": {
    "total": 0,
    "by_severity": { "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0 },
    "by_owasp": {}
  },
  "non_security_observations": []
}
```

---

## Example 4 — Ambiguous IDOR (NEEDS_HUMAN, incomplete trace)

**Input diff**:

```diff
diff --git a/api/src/routes/profile.ts b/api/src/routes/profile.ts
--- a/api/src/routes/profile.ts
+++ b/api/src/routes/profile.ts
@@ -10,6 +10,10 @@ router.get('/profile/:id', async (req, res) => {
   const profile = await Profile.findById(req.params.id);
   res.json(profile);
 });
+
+router.post('/profile/:id/avatar', async (req, res) => {
+  await Profile.update({ avatarUrl: req.body.url }, { where: { id: req.params.id } });
+  res.json({ ok: true });
+});
```

**Expected output**:

```json
{
  "schema_version": "1.0",
  "findings": [
    {
      "rule_id": "B-11",
      "owasp_id": "A01",
      "cwe_id": "CWE-639",
      "severity": "high",
      "confidence": "medium",
      "verdict": "NEEDS_HUMAN",
      "file": "api/src/routes/profile.ts",
      "line": 14,
      "evidence": "router.post('/profile/:id/avatar', async (req, res) => {\n  await Profile.update({ avatarUrl: req.body.url }, { where: { id: req.params.id } });",
      "exploit_trace": [
        "source: req.params.id — URL parameter, fully attacker-controlled",
        "sink: Profile.update({...}, { where: { id: req.params.id } }) — mutates any profile by id",
        "missing guard: UNKNOWN — no ownership check is visible inside this hunk, but route-level auth middleware (e.g. `router.use(requireOwner)`) could exist outside the diff"
      ],
      "rationale": "Endpoint updates a profile by id from URL params without any visible authorization check in this diff. If route-level middleware enforces `req.user.id === req.params.id`, this is fine; otherwise it is IDOR (anyone can change anyone's avatar).",
      "remediation": "Add explicit ownership check inside the handler: `if (req.params.id !== req.user.id) return res.status(403).end();` or add an authz middleware. See https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html",
      "title": "Possible IDOR — avatar update without visible authorization check"
    }
  ],
  "summary": {
    "total": 1,
    "by_severity": { "critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0 },
    "by_owasp": { "A01": 1 }
  },
  "non_security_observations": [
    "Two new endpoints share an `:id` URL param pattern; consider centralizing the authorization check in a router-level middleware to avoid forgetting it on future endpoints."
  ]
}
```

Note how the `missing guard` element is explicitly tagged `UNKNOWN` — that is what drops the confidence to `medium` and the verdict to `NEEDS_HUMAN`. Do not invent a guard you cannot see.

---

## Example 5 — Sanitizer removal regression (R-01)

**Input diff**:

```diff
diff --git a/apps/web/src/Markdown.tsx b/apps/web/src/Markdown.tsx
--- a/apps/web/src/Markdown.tsx
+++ b/apps/web/src/Markdown.tsx
@@ -1,9 +1,8 @@
 import { marked } from 'marked';
-import DOMPurify from 'dompurify';

 export function Markdown({ source }: { source: string }) {
   const html = marked.parse(source);
-  const safe = DOMPurify.sanitize(html);
-  return <div dangerouslySetInnerHTML={{ __html: safe }} />;
+  return <div dangerouslySetInnerHTML={{ __html: html }} />;
 }
```

**Expected output**:

```json
{
  "schema_version": "1.0",
  "findings": [
    {
      "rule_id": "R-01",
      "owasp_id": "A05",
      "cwe_id": "CWE-79",
      "severity": "high",
      "confidence": "high",
      "verdict": "TRUE_POSITIVE",
      "file": "apps/web/src/Markdown.tsx",
      "line": 7,
      "evidence": "return <div dangerouslySetInnerHTML={{ __html: html }} />;",
      "exploit_trace": [
        "source: `source` prop → marked.parse(source) → html (raw HTML rendered from user-supplied markdown)",
        "sink: dangerouslySetInnerHTML={{ __html: html }} on the returned <div>",
        "missing guard: the DOMPurify.sanitize() call was deleted in this same hunk (visible '-' lines)"
      ],
      "rationale": "The diff removes the DOMPurify sanitizer step that was protecting the markdown-rendered HTML. Now the raw marked output flows directly into `dangerouslySetInnerHTML`, exposing DOM XSS via crafted markdown (e.g., `<img src=x onerror=...>`).",
      "remediation": "Re-add the DOMPurify import and sanitization step: `const safe = DOMPurify.sanitize(html);` then use `safe` in dangerouslySetInnerHTML. Alternatively, configure `marked` with `{ sanitize: true }` if using a version that supports it. See https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
      "title": "DOM XSS regression — DOMPurify sanitization removed from Markdown component"
    }
  ],
  "summary": {
    "total": 1,
    "by_severity": { "critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0 },
    "by_owasp": { "A05": 1 }
  },
  "non_security_observations": []
}
```

---

## Example 6 — Self-critique downgrade (FALSE_POSITIVE)

This example shows the self-critique pass at work. On a first read, the diff looks like a path-traversal sink (`req.query.name` flowing into `fs.readFileSync`). The self-critique pass spots a guard introduced **in the same hunk** that closes the chain, so the finding is suppressed and the concern is moved to `non_security_observations` instead.

**Input diff**:

```diff
diff --git a/api/src/routes/template.ts b/api/src/routes/template.ts
--- a/api/src/routes/template.ts
+++ b/api/src/routes/template.ts
@@ -3,7 +3,10 @@ import fs from 'node:fs';
 import path from 'node:path';

 router.get('/template/:name', (req, res) => {
-  const data = fs.readFileSync(`/srv/templates/${req.params.name}`, 'utf8');
+  const safeName = path.basename(req.params.name);
+  if (!/^[a-z0-9_-]+\.tmpl$/.test(safeName)) return res.status(400).end();
+  const data = fs.readFileSync(path.join('/srv/templates', safeName), 'utf8');
   res.json({ data });
 });
```

**Expected output**:

```json
{
  "schema_version": "1.0",
  "findings": [],
  "summary": {
    "total": 0,
    "by_severity": { "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0 },
    "by_owasp": {}
  },
  "non_security_observations": [
    "Path-traversal hardening: the new code adds `path.basename()` + a strict regex allowlist before passing the filename to fs. This closes the prior CWE-22 exposure visible in the deleted line — no security finding to emit."
  ]
}
```

What the self-critique pass produced internally (do not emit this in real output):

> Initial candidate: B-05 (path traversal), source `req.params.name`, sink `fs.readFileSync`.
> Self-critique step 3 (is there a guard?): yes — `path.basename()` strips traversal components, AND a regex allowlist `^[a-z0-9_-]+\.tmpl$` constrains the filename, AND `path.join` with a fixed base directory is used. The chain is closed inside the diff. Drop the finding; surface the hardening fact in `non_security_observations` so a reviewer can confirm the fix is intentional.

---

## Example 7 — Prototype pollution (R-05, NOT B-05 path traversal)

This example exists because in practice the LLM has a tendency to misclassify prototype pollution as path traversal — both involve walking a sequence of string keys. The distinguishing signal is **what is being walked**: filesystem paths (`fs.readFileSync(path)`) versus JavaScript object property chains (`obj[k1][k2] = v`). When you see `__proto__`, `prototype`, or `constructor` in the data flow, or a recursive `Object.assign`/`deepMerge` that does not deny those keys — that is **R-05**, not B-05.

**Input diff**:

```diff
diff --git a/src/cli/args.ts b/src/cli/args.ts
--- a/src/cli/args.ts
+++ b/src/cli/args.ts
@@ -1,8 +1,7 @@
 export function setDeep(obj: any, path: string[], value: unknown) {
-  if (path[0] === '__proto__' || path[0] === 'prototype' || path[0] === 'constructor') return;
   let cur = obj;
   for (let i = 0; i < path.length - 1; i++) {
     if (cur[path[i]] === undefined) cur[path[i]] = {};
     cur = cur[path[i]];
   }
   cur[path[path.length - 1]] = value;
 }
```

**Expected output**:

```json
{
  "schema_version": "1.0",
  "findings": [
    {
      "rule_id": "R-05",
      "owasp_id": "A08",
      "cwe_id": "CWE-1321",
      "severity": "high",
      "confidence": "high",
      "verdict": "TRUE_POSITIVE",
      "file": "src/cli/args.ts",
      "line": 2,
      "evidence": "for (let i = 0; i < path.length - 1; i++) {\n    if (cur[path[i]] === undefined) cur[path[i]] = {};",
      "exploit_trace": [
        "source: attacker-supplied `path` array (typically from CLI flags or HTTP body parsed into dotted notation)",
        "sink: recursive object-property walk that writes through path[i] (line 4) into the prototype chain via __proto__/constructor/prototype keys",
        "missing guard: the explicit denylist of __proto__/prototype/constructor was REMOVED in this diff (visible '-' line)"
      ],
      "rationale": "The diff strips the denylist of dangerous keys before the recursive object walk. A poisoned input like {path:['__proto__','isAdmin'], value:true} now writes to Object.prototype.isAdmin, corrupting every object in the runtime. This is prototype pollution (CWE-1321), NOT path traversal (CWE-22) — there is no filesystem in the chain.",
      "remediation": "Restore the denylist of __proto__, prototype, constructor — and consider using a Map or Object.create(null) target to make pollution structurally impossible. See https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Prototype_Pollution_Prevention_Cheat_Sheet.md",
      "title": "Prototype pollution — denylist removed from deep-set utility"
    }
  ],
  "summary": {
    "total": 1,
    "by_severity": { "critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0 },
    "by_owasp": { "A08": 1 }
  },
  "non_security_observations": []
}
```

Decision rule for the classifier:

> **R-05 (prototype pollution) vs B-05 (path traversal)** —
> If the data flow ends in `fs.*`, `path.*`, or a filesystem URI → B-05.
> If the data flow ends in `obj[k]`, `Object.assign`, recursive merge, `_.set`, `defaultsDeep` → R-05.
> Names that look traversal-shaped (`path`, `parts`, `keys`) are not a B-05 signal on their own.

---

## Example 8 — Repository-pattern refactor is a TRUE NEGATIVE

A frequent false-positive trap: a route handler that forwards `req.body` into an ORM call **looks** like mass assignment (B-13) on first glance. But if the helper / repository it forwards into applies an explicit field allowlist, the chain is closed and no finding should be emitted. The signal that closes the chain may live in a **new file** introduced in the same diff — the analyzer must read the other files in the diff before deciding.

**Input diff**:

```diff
diff --git a/api/src/routes/users.ts b/api/src/routes/users.ts
--- a/api/src/routes/users.ts
+++ b/api/src/routes/users.ts
@@ -1,5 +1,6 @@
 import { Router } from 'express';
-import { updateUserDirect } from '../services/user';
+import { UserRepository } from '../repositories/UserRepository';
+const repo = new UserRepository();

 router.patch('/users/me/profile', requireAuth, async (req, res) => {
-  await updateUserDirect(req.user!.id, req.body);
+  await repo.updateProfile(req.user!.id, req.body);
   res.json({ ok: true });
 });
diff --git a/api/src/repositories/UserRepository.ts b/api/src/repositories/UserRepository.ts
new file mode 100644
--- /dev/null
+++ b/api/src/repositories/UserRepository.ts
@@ -0,0 +1,12 @@
+import { User } from '../models/User';
+
+const PROFILE_FIELDS = ['displayName', 'bio', 'avatarUrl'] as const;
+
+export class UserRepository {
+  updateProfile(id: string, fields: Partial<Record<typeof PROFILE_FIELDS[number], string>>) {
+    const safe: Record<string, string> = {};
+    for (const k of PROFILE_FIELDS) if (fields[k] !== undefined) safe[k] = fields[k]!;
+    return User.update(safe, { where: { id } });
+  }
+}
```

**Expected output**:

```json
{
  "schema_version": "1.0",
  "findings": [],
  "summary": {
    "total": 0,
    "by_severity": { "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0 },
    "by_owasp": {}
  },
  "non_security_observations": [
    "Repository-pattern refactor preserves the field allowlist by moving it into UserRepository.updateProfile (PROFILE_FIELDS constant). The route handler now forwards req.body into the repository, but the repository copies only whitelisted keys into the ORM call. Net change is structural, not security-relevant."
  ]
}
```

Self-critique commentary (do not emit):

> Initial candidate: B-13 (mass assignment) on the route — `req.body` reaches `User.update` indirectly.
> Self-critique step 3 (is there a guard?): YES, inside the new UserRepository.ts file. PROFILE_FIELDS is the allowlist; the `for (const k of PROFILE_FIELDS) if (...)` loop copies only those keys. The chain is closed across the two files in this diff. Drop the finding.

Decision rule:

> Before emitting B-13 on a `req.body` → ORM `.update()/.create()/.findOrCreate()` flow, **scan every file in the diff** for a const array or Zod/Joi/Yup/Valibot schema named like `*_FIELDS`, `*_SCHEMA`, `pick`, `whitelist`. If such an allowlist exists and is applied before the ORM call, the finding is a FALSE_POSITIVE (or simply not emitted).

---

## Example 9 — NoSQL injection via Mongoose `$where` (B-03, NOT B-01)

A common misclassification: any template-string in a query call gets labelled as SQL injection (B-01). The distinguishing signal is **the API used**, not the string-concatenation pattern. Mongoose, Mongo driver, and other NoSQL clients have their own injection class.

`$where` in Mongoose evaluates the string as **JavaScript inside MongoDB** — interpolating user input there is a NoSQL-injection-to-RCE chain. The catalog rule for this is B-03 (NoSQL injection), not B-01 (SQL injection).

**Input diff**:

```diff
diff --git a/api/src/queries/search.ts b/api/src/queries/search.ts
--- a/api/src/queries/search.ts
+++ b/api/src/queries/search.ts
@@ -1,7 +1,6 @@
 import { Product } from '../models/Product';

 export async function searchProducts(req, res) {
   const q = req.query.q as string;
-  const safe = q.replace(/[^\w\s-]/g, '');
-  const results = await Product.find({ $text: { $search: safe } });
+  const results = await Product.find({ $where: `this.name.includes('${q}')` });
   res.json(results);
 }
```

**Expected output**:

```json
{
  "schema_version": "1.0",
  "findings": [
    {
      "rule_id": "B-03",
      "owasp_id": "A05",
      "cwe_id": "CWE-943",
      "severity": "critical",
      "confidence": "high",
      "verdict": "TRUE_POSITIVE",
      "file": "api/src/queries/search.ts",
      "line": 6,
      "evidence": "Product.find({ $where: `this.name.includes('${q}')` })",
      "exploit_trace": [
        "source: req.query.q — fully attacker-controlled HTTP query string",
        "sink: Mongoose `$where` operator evaluating the interpolated template as server-side JavaScript inside MongoDB",
        "missing guard: the prior regex sanitiser was removed in this same hunk; nothing sanitises the input before it reaches $where"
      ],
      "rationale": "Mongoose's `$where` evaluates its argument as JavaScript server-side in MongoDB. Interpolating user input into that string is NoSQL injection — payloads like `'); return require('child_process')...//` achieve code execution on the database server. The earlier $text+regex path used a real index and rejected metacharacters; deleting it removed the only guard.",
      "remediation": "Avoid `$where` entirely. Use indexed `$text` with a regex-sanitised input, or compile the query with `$regex` on a specific field. See https://cheatsheetseries.owasp.org/cheatsheets/NoSQL_Database_Security_Cheat_Sheet.html",
      "title": "NoSQL injection — user input interpolated into Mongoose $where"
    }
  ],
  "summary": {
    "total": 1,
    "by_severity": { "critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0 },
    "by_owasp": { "A05": 1 }
  },
  "non_security_observations": []
}
```

Decision rule:

> **B-01 (SQL) vs B-03 (NoSQL)** — choose based on the ORM / driver, not the string shape:
> - `sequelize.query`, `db.query`, `pool.query`, `client.query`, `pg.*`, `mysql.*` → B-01
> - `Mongoose.find/$where`, `MongoClient.*`, `db.collection(...).find`, `$expr` with user input → B-03

---

## Example 10 — Sanitizer-shaped API is not a sanitizer (`R-01`)

A subtle FN trap: the diff still calls `DOMPurify.sanitize()` so a fast scan stops there. But `ADD_TAGS: ['script']` + `ADD_ATTR: ['onerror', ...]` defeat the sanitizer — the function looks like protection but allows the exact vectors it normally strips. Same applies to homemade `sanitize(s) => s` identity functions, validator libraries called with `{ disable: ['xss-rule'] }`, or escape() routines that whitelist `<script>` as "safe HTML".

The signal to look for is **dangerous configuration on a protection API**, not the absence of the API call.

**Input diff**:

```diff
diff --git a/web/src/lib/markdown.ts b/web/src/lib/markdown.ts
--- a/web/src/lib/markdown.ts
+++ b/web/src/lib/markdown.ts
@@ -1,5 +1,8 @@
 import { marked } from 'marked';
 import DOMPurify from 'isomorphic-dompurify';

 export function renderMarkdown(source: string): string {
-  return DOMPurify.sanitize(marked.parse(source) as string);
+  return DOMPurify.sanitize(marked.parse(source) as string, {
+    ADD_TAGS: ['iframe', 'script'],
+    ADD_ATTR: ['onerror', 'onload', 'srcdoc'],
+  });
 }
```

**Expected output**:

```json
{
  "schema_version": "1.0",
  "findings": [
    {
      "rule_id": "R-01",
      "owasp_id": "A05",
      "cwe_id": "CWE-79",
      "severity": "critical",
      "confidence": "high",
      "verdict": "TRUE_POSITIVE",
      "file": "web/src/lib/markdown.ts",
      "line": 5,
      "evidence": "DOMPurify.sanitize(marked.parse(source) as string, {\n    ADD_TAGS: ['iframe', 'script'],\n    ADD_ATTR: ['onerror', 'onload', 'srcdoc'],\n  });",
      "exploit_trace": [
        "source: `source` markdown string (typically user-supplied through comment / post editor)",
        "sink: callers render the returned HTML via dangerouslySetInnerHTML or el.innerHTML; the function name promises sanitisation",
        "missing guard: DOMPurify is invoked but configured to PERMIT `script`, `iframe`, and `onerror`/`onload`/`srcdoc` — the configuration negates the protection. There is no effective sanitiser between source and sink despite appearances."
      ],
      "rationale": "Calling DOMPurify with `ADD_TAGS: ['script']` and `ADD_ATTR: ['onerror', 'onload']` allowlists the exact attack vectors the library normally strips. This is sanitisation theatre — a passing test (`expect(sanitize('<script>...')).toContain('script')`) would now be vacuous. Any caller relying on the function's name is now exposed to DOM XSS.",
      "remediation": "Remove the ADD_TAGS / ADD_ATTR overrides. If specific HTML features must be supported (e.g., embeds), use a dedicated allowlist of safe tags only and never include `script` / event-handler attributes. See https://github.com/cure53/DOMPurify#hooks.",
      "title": "XSS — DOMPurify configured to allow script tags and event-handler attributes (sanitisation theatre)"
    }
  ],
  "summary": {
    "total": 1,
    "by_severity": { "critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0 },
    "by_owasp": { "A05": 1 }
  },
  "non_security_observations": []
}
```

Decision rule:

> Treat **any change to a sanitiser's allowlist / blacklist / configuration** as security-relevant. Common patterns to flag:
> - `DOMPurify.sanitize(x, { ADD_TAGS / ADD_ATTR / ALLOWED_*  / FORBID_*  })` — investigate the value, not just the call
> - Validator libraries called with `{ disable: [...] }` or `{ skip: [...] }`
> - Homemade `sanitize`/`escape`/`clean` that delegate to identity (`const sanitize = (s) => s;`)
> - `safe-eval` / `vm.runInContext` configured without sandbox restrictions
