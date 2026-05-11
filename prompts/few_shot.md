# Few-shot examples for security-audit diff analysis

Below are 5 example diffs and the expected JSON output. They cover:
- (1) clear vulnerability introduction
- (2) refactor that adds a new vulnerability
- (3) safe refactor (no findings)
- (4) ambiguous case (NEEDS_HUMAN)
- (5) sanitizer removal regression

These are injected into the LLM prompt so the model has concrete grounding for tone, structure, and verdict discipline.

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
      "owasp_id": "A03:2021",
      "cwe_id": "CWE-79",
      "severity": "high",
      "confidence": "high",
      "verdict": "TRUE_POSITIVE",
      "file": "apps/web/src/components/Comment.tsx",
      "line": 13,
      "evidence": "<p ref={(el) => el && (el.innerHTML = comment.body)} />",
      "rationale": "The change replaces safe React text rendering with direct `innerHTML` assignment from user-supplied `comment.body`. Any HTML in a comment will execute as code in the user's browser.",
      "remediation": "Revert to JSX text interpolation (`<p>{comment.body}</p>`) which auto-escapes, or sanitize with DOMPurify: `el.innerHTML = DOMPurify.sanitize(comment.body)`. See https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
      "title": "DOM XSS via innerHTML with user-supplied comment body"
    }
  ],
  "summary": {
    "total": 1,
    "by_severity": { "critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0 },
    "by_owasp": { "A03:2021": 1 }
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
      "owasp_id": "A10:2021",
      "cwe_id": "CWE-918",
      "severity": "high",
      "confidence": "high",
      "verdict": "TRUE_POSITIVE",
      "file": "api/src/services/preview.ts",
      "line": 8,
      "evidence": "const url = req.query.target as string;\n   const r = await axios.get(url);",
      "rationale": "The diff removes an allowlist (`WHITELIST[req.query.target]`) and passes `req.query.target` directly to `axios.get`. An attacker can now make the server fetch arbitrary internal URLs (cloud metadata, RDS, internal admin panels).",
      "remediation": "Restore the allowlist of permitted target URLs, or validate `req.query.target` against a strict pattern (e.g., scheme=https, host in {allowed_hosts}). See https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
      "title": "SSRF — allowlist removed, user-controlled URL passed to axios.get"
    }
  ],
  "summary": {
    "total": 1,
    "by_severity": { "critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0 },
    "by_owasp": { "A10:2021": 1 }
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

## Example 4 — Ambiguous case (NEEDS_HUMAN)

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
      "owasp_id": "A01:2021",
      "cwe_id": "CWE-639",
      "severity": "high",
      "confidence": "medium",
      "verdict": "NEEDS_HUMAN",
      "file": "api/src/routes/profile.ts",
      "line": 14,
      "evidence": "router.post('/profile/:id/avatar', async (req, res) => {\n  await Profile.update({ avatarUrl: req.body.url }, { where: { id: req.params.id } });",
      "rationale": "Endpoint updates a profile by id from URL params without any visible authorization check in this diff. If route-level middleware enforces `req.user.id === req.params.id`, this is fine; otherwise it is IDOR (anyone can change anyone's avatar).",
      "remediation": "Add explicit ownership check inside the handler: `if (req.params.id !== req.user.id) return res.status(403).end();` or add an authz middleware. See https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html",
      "title": "Possible IDOR — avatar update without visible authorization check"
    }
  ],
  "summary": {
    "total": 1,
    "by_severity": { "critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0 },
    "by_owasp": { "A01:2021": 1 }
  },
  "non_security_observations": [
    "Two new endpoints share an `:id` URL param pattern; consider centralizing the authorization check in a router-level middleware to avoid forgetting it on future endpoints."
  ]
}
```

---

## Example 5 — Sanitizer removal regression

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
      "owasp_id": "A03:2021",
      "cwe_id": "CWE-79",
      "severity": "high",
      "confidence": "high",
      "verdict": "TRUE_POSITIVE",
      "file": "apps/web/src/Markdown.tsx",
      "line": 7,
      "evidence": "return <div dangerouslySetInnerHTML={{ __html: html }} />;",
      "rationale": "The diff removes the DOMPurify sanitizer step that was protecting the markdown-rendered HTML. Now the raw marked output flows directly into `dangerouslySetInnerHTML`, exposing DOM XSS via crafted markdown (e.g., `<img src=x onerror=...>`).",
      "remediation": "Re-add the DOMPurify import and sanitization step: `const safe = DOMPurify.sanitize(html);` then use `safe` in dangerouslySetInnerHTML. Alternatively, configure `marked` with `{ sanitize: true }` if using a version that supports it. See https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
      "title": "DOM XSS regression — DOMPurify sanitization removed from Markdown component"
    }
  ],
  "summary": {
    "total": 1,
    "by_severity": { "critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0 },
    "by_owasp": { "A03:2021": 1 }
  },
  "non_security_observations": []
}
```
