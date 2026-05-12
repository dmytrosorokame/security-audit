# Vulnerability Pattern Catalog — LLM Grounding

This catalog describes the **34 vulnerability patterns** the LLM agent looks for when reviewing diffs. Each entry has: OWASP Top 10 (2021) category, CWE ID, severity, a plain-English description of what the pattern looks like, vulnerable and safe code examples, confidence guidance, a remediation summary, and a reference URL.

## How the LLM uses this

When reviewing a diff, the agent grounds its reasoning in this catalog. The decision flow per finding is:

1. **Match a pattern below?** Use that `rule_id` (e.g. `R-02`) and inherit its canonical `owasp_id`, `cwe_id`, and `severity`.
2. **Real vulnerability but no catalog match?** Use `rule_id: NEW_PATTERN`, fill in `owasp_id` and `cwe_id` yourself, set `verdict: NEEDS_HUMAN` unless the pattern is unambiguous.
3. **Pattern is present but the diff actually fixes / sanitizes it?** Don't flag (or flag with `verdict: FALSE_POSITIVE` if the construct is novel and could regress).

Code examples are illustrative — they show the *shape* of the pattern, not exhaustive variations. The LLM is expected to recognize the pattern across syntactic variants (e.g. arrow functions, async, destructuring).

## Coverage

| Tier | Rules | OWASP coverage |
|---|---|---|
| Frontend (R-XX) | R-01 … R-11 | A01, A02, A03, A04, A05, A07, A08 |
| Backend (B-XX) | B-01 … B-15 | A01, A02, A03, A05, A07, A08, A10 |
| Container (D-XX) | D-01 … D-08 | A04, A05, A06, A07 |

Total: 34 rules across 9 of 10 OWASP categories. (A09 Logging & Monitoring is operational, not code-level — out of scope for diff review.)

---

# Frontend rules (R-XX)

## R-01 — Unsanitized `dangerouslySetInnerHTML`

**OWASP** A03:2021 (Injection) · **CWE** CWE-79 · **Severity** high

React's `dangerouslySetInnerHTML={{__html: x}}` renders `x` as raw HTML, bypassing JSX text escaping. If `x` is user-controlled (URL params, GraphQL response, user comments, markdown render output), the attacker injects `<script>` or event-handler attributes and executes JavaScript in the victim's browser.

**Vulnerable**:
```tsx
<div dangerouslySetInnerHTML={{ __html: comment.body }} />
<article dangerouslySetInnerHTML={{ __html: marked.parse(post.markdown) }} />
```

**Safe**:
```tsx
<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(comment.body) }} />
// or skip raw HTML entirely:
<div>{comment.body}</div>   // JSX auto-escapes
```

**Confidence guidance**: if the value is a hardcoded literal or an imported constant (`import { COPY } from './copy'`), downgrade to `confidence: low` or use `verdict: NEEDS_HUMAN`. Genuine sanitizer calls (`DOMPurify.sanitize`, `sanitizeHtml`, `xss`) on the value mean the diff is safe.

**Fix**: Wrap with `DOMPurify.sanitize(html, { ALLOWED_TAGS: [...] })`, or render as plain text.

**Reference**: <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html>

---

## R-02 — DOM injection via `innerHTML` / `outerHTML` / `document.write`

**OWASP** A03:2021 · **CWE** CWE-79 · **Severity** high

Direct DOM writes from non-literal values. Includes `el.innerHTML = x`, `el.outerHTML = x`, `el.insertAdjacentHTML(pos, x)`, `document.write(x)`, `document.writeln(x)`. Same XSS category as R-01 but outside React's JSX path.

**Vulnerable**:
```ts
container.innerHTML = userBio;
document.write('<h1>' + req.query.title + '</h1>');
el.insertAdjacentHTML('beforeend', response.html);
```

**Safe**:
```ts
container.textContent = userBio;          // text-only, never parsed
container.innerHTML = DOMPurify.sanitize(userBio);
el.replaceChildren(document.createTextNode(userBio));
```

**Confidence guidance**: assignments where the right-hand side is a string literal (`el.innerHTML = '<br>'`) are safe. Calls that pass a sanitizer output are safe.

**Fix**: prefer `textContent` for plain text, or sanitize before assignment.

**Reference**: <https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html>

---

## R-03 — `target="_blank"` without `rel="noopener"` (tabnabbing)

**OWASP** A05:2021 · **CWE** CWE-1022 · **Severity** medium

Links that open in a new tab without `rel="noopener noreferrer"` let the destination page access `window.opener` in the parent, enabling reverse tabnabbing (the new tab can redirect the original tab to a phishing clone). Modern browsers ship implicit `noopener` for `target="_blank"` on most sites, but the explicit attribute is the right defense.

**Vulnerable**:
```tsx
<a href={post.url} target="_blank">Read more</a>
<a href="https://external.com" target="_blank" rel="noreferrer">…</a>  // noreferrer alone is not enough
```

**Safe**:
```tsx
<a href={post.url} target="_blank" rel="noopener noreferrer">Read more</a>
```

**Confidence guidance**: if `rel` is set dynamically (`rel={someVar}`) we can't tell from the diff alone — downgrade confidence. Internal links (same origin) are lower risk but still good hygiene.

**Fix**: always include `rel="noopener"` (and `noreferrer` for cross-origin privacy).

**Reference**: <https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html#tabnabbing>

---

## R-04 — `javascript:` URL in `href` / `src`

**OWASP** A03:2021 · **CWE** CWE-79 · **Severity** high

URL attributes whose value starts with `javascript:` execute the rest as JavaScript when clicked. Often slipped in via user-controlled URL fields.

**Vulnerable**:
```tsx
<a href="javascript:alert(1)">Click</a>
<a href={post.callback}>…</a>                     // when post.callback can be "javascript:…"
<iframe src={userProfile.website} />              // same risk
```

**Safe**:
```tsx
const href = /^https?:\/\//.test(post.callback) ? post.callback : '#';
<a href={href}>…</a>
```

**Confidence guidance**: hardcoded `javascript:`-URL is unambiguous TP. Dynamic href whose value can't be inspected requires `NEEDS_HUMAN`.

**Fix**: validate URL scheme on input (`new URL(value).protocol === 'https:'`); reject `javascript:`, `data:`, `vbscript:` schemes.

**Reference**: <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html#rule-5-url-escape-before-inserting-untrusted-data-into-html-url-parameter-values>

---

## R-05 — Prototype pollution patterns

**OWASP** A08:2021 · **CWE** CWE-1321 · **Severity** high

Recursive merge or `Object.assign({}, untrusted)` where untrusted carries `__proto__`, `constructor`, or `prototype` keys mutates `Object.prototype` globally, leading to logic bypass, auth bypass, or RCE depending on downstream consumers.

**Vulnerable**:
```ts
const config = Object.assign({}, defaults, JSON.parse(req.body));
function deepMerge(t, s) { for (const k in s) t[k] = (typeof s[k] === 'object') ? deepMerge(t[k] || {}, s[k]) : s[k]; }
```

**Safe**:
```ts
const config = { ...defaults, ...sanitize(JSON.parse(req.body)) };
function safeMerge(t, s) {
  for (const k of Object.keys(s)) {
    if (k === '__proto__' || k === 'constructor' || k === 'prototype') continue;
    // …
  }
}
// Or use Object.create(null), lodash.mergeWith with a customizer, or Immer.
```

**Confidence guidance**: bare `Object.assign({}, x)` where `x` is clearly typed and not from user input is safe. Recursive merge with no key check on user-controlled input is a strong TP.

**Fix**: validate keys against an allowlist before merge; use `Object.create(null)` for untrusted maps.

**Reference**: <https://github.com/HoLyVieR/prototype-pollution-nsec18>

---

## R-06 — Tokens / secrets in `localStorage` or `sessionStorage`

**OWASP** A02:2021 · **CWE** CWE-922 · **Severity** high

Storing JWTs, refresh tokens, API keys, or session credentials in `localStorage` / `sessionStorage` exposes them to any XSS — including 3rd-party scripts on the page. Use httpOnly cookies for session credentials.

**Vulnerable**:
```ts
localStorage.setItem('jwt', response.token);
sessionStorage.setItem('refreshToken', refresh);
window.localStorage.setItem('api_key', user.apiKey);
```

**Safe**:
```ts
// Have the server set an httpOnly, Secure, SameSite cookie:
// Set-Cookie: session=...; HttpOnly; Secure; SameSite=Lax
// Client side never touches the token directly.
```

**Confidence guidance**: keys named `theme`, `lang`, `consent`, `lastVisited` are not secrets. Trigger on key names containing `token`, `jwt`, `secret`, `password`, `credential`, `auth`, `api_key`. Test files (`*.test.ts`, `*.spec.ts`) are usually fine to ignore.

**Fix**: move session tokens to httpOnly cookies set by the server; for non-session API keys, fetch short-lived ones from an authenticated endpoint and keep in memory only.

**Reference**: <https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html#local-storage>

---

## R-07 — Hardcoded secrets / API keys

**OWASP** A07:2021 · **CWE** CWE-798 · **Severity** critical

API keys, OAuth client secrets, JWT signing keys, AWS credentials embedded in client-side or shared source. Even in private repos they leak via build artifacts, git history, error logs. Recognizable formats: `AKIA…` (AWS), `AIza…` (Google), `sk_live_…`/`pk_live_…` (Stripe), `xox[abp]-…` (Slack), `ghp_…` (GitHub PAT), `eyJ…` (JWT), `-----BEGIN … PRIVATE KEY-----`.

**Vulnerable**:
```ts
const stripe = new Stripe('sk_live_51Hxxxxxxxxxxxxxxxxxxxxxx');
const config = { awsKey: 'AKIAIOSFODNN7EXAMPLE', awsSecret: 'wJalrXUtnFEMI/...' };
const TOKEN = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ...';
```

**Safe**:
```ts
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);
// .env (gitignored):
// STRIPE_SECRET_KEY=sk_live_...
// Or pull from AWS Secrets Manager, Vault, Doppler, etc.
```

**Confidence guidance**: strings that look like real secrets (high entropy, match known prefixes) are TP with high confidence. Strings labeled `test`, `dummy`, `example`, `xxx`, `your_api_key_here` are FP. URLs, human-readable identifiers like `'A2: Broken Auth'`, route paths like `'/api/v1'` are not secrets.

**Fix**: rotate the leaked secret immediately, then read from `process.env` or a secret manager. Add the leaked value to `.gitleaks.toml` or similar to prevent re-introduction.

**Reference**: <https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html>

---

## R-08 — Open redirect via `window.location = userInput`

**OWASP** A01:2021 · **CWE** CWE-601 · **Severity** high

Setting `window.location`, `window.location.href`, `location.assign(...)`, or `location.replace(...)` to a URL derived from query string, route params, or `postMessage` payload lets an attacker redirect the victim to a phishing page after a legitimate-looking entry URL.

**Vulnerable**:
```ts
const next = new URLSearchParams(location.search).get('next') || '/';
window.location.href = next;                       // attacker sends ?next=https://evil.com

router.replace(props.location.state?.from);        // unvalidated origin
```

**Safe**:
```ts
const next = new URLSearchParams(location.search).get('next') || '/';
// Allow only same-origin paths:
window.location.href = next.startsWith('/') && !next.startsWith('//') ? next : '/';
// Or whitelist allowed hosts:
const allowed = new Set(['app.example.com', 'admin.example.com']);
const url = new URL(next, location.origin);
window.location.href = allowed.has(url.host) ? url.href : '/';
```

**Confidence guidance**: redirect targets sourced from `location.search`, `URLSearchParams`, `router.query`, `props.location.state` are tainted. Targets that are hardcoded literals or come from authenticated server responses are usually safe.

**Fix**: validate the target is a relative path or a host in an explicit allowlist; never trust the raw value.

**Reference**: <https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html>

---

## R-09 — `postMessage` without origin validation

**OWASP** A04:2021 · **CWE** CWE-346 · **Severity** high

Two patterns: (a) `addEventListener('message', handler)` where `handler` doesn't check `event.origin` accepts messages from any iframe/window; (b) `target.postMessage(data, '*')` broadcasts to any origin embedding the iframe. Both expose a cross-origin attack surface.

**Vulnerable**:
```ts
window.addEventListener('message', (e) => {
  doStuff(e.data);                                  // no e.origin check
});

iframe.contentWindow.postMessage({ token }, '*');   // wildcard target
```

**Safe**:
```ts
const ALLOWED_ORIGIN = 'https://parent.example.com';
window.addEventListener('message', (e) => {
  if (e.origin !== ALLOWED_ORIGIN) return;
  doStuff(e.data);
});

iframe.contentWindow.postMessage({ token }, ALLOWED_ORIGIN);
```

**Confidence guidance**: `e.origin === '...'`, `e.origin.startsWith('https://...')`, or `e.origin in ALLOWED` inside the handler count as guarding. Wildcard `'*'` in `postMessage` is unconditionally a TP.

**Fix**: pin to an exact origin (or set of origins); never use `'*'`.

**Reference**: <https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html#web-messaging>

---

## R-10 — Missing CSP / SRI on HTML documents

**OWASP** A05:2021 · **CWE** CWE-693 · **Severity** medium

HTML documents shipped without a Content-Security-Policy `<meta>` tag (and without server CSP headers) provide no defense in depth against XSS. External `<script src>` without `integrity="sha384-..."` (SRI) lets a compromised CDN ship attacker-controlled JS.

**Vulnerable**:
```html
<!doctype html>
<html><head>
  <script src="https://cdn.example.com/lib.js"></script>
</head>...
```

**Safe**:
```html
<!doctype html>
<html><head>
  <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' 'sha256-...'">
  <script src="https://cdn.example.com/lib.js" integrity="sha384-..." crossorigin="anonymous"></script>
</head>...
```

**Confidence guidance**: only flag full HTML documents (containing `<!doctype html>` or `<html>`). Framework component templates (`.vue`, `.svelte`, Angular partials) are not full documents — skip. CSP delivered via server header instead of meta tag is also valid; if the diff only shows HTML, assume the server might or might not set it (`NEEDS_HUMAN`).

**Fix**: add a meta CSP or configure the server to send the CSP header; add `integrity` + `crossorigin` to every external `<script>` and `<link rel=stylesheet>`.

**Reference**: <https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html>

---

## R-11 — CORS misconfiguration in client fetch

**OWASP** A05:2021 · **CWE** CWE-942 · **Severity** high

`fetch(url, { credentials: 'include', mode: 'no-cors' })` or `credentials: 'include'` against an endpoint that responds with `Access-Control-Allow-Origin: *` defeats the cross-origin protection. The client may be unintentionally sending session cookies to third-party endpoints.

**Vulnerable**:
```ts
fetch('https://api.partner.com/me', {
  credentials: 'include',
  mode: 'no-cors',
});
```

**Safe**:
```ts
fetch('https://api.partner.com/me', {
  credentials: 'include',                         // only when same-origin or partner is trusted
  mode: 'cors',                                   // explicit CORS
});
// Server must return Access-Control-Allow-Origin: <exact-origin>, not '*'.
```

**Confidence guidance**: `credentials: 'include'` alone is fine. Combined with `mode: 'no-cors'` or wildcard-origin Access-Control headers, it's a TP.

**Fix**: drop `credentials: 'include'` for non-authenticated requests; use `mode: 'cors'` with an exact-origin server response.

**Reference**: <https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html>

---

# Backend rules (B-XX)

## B-01 — SQL injection via raw query with user input

**OWASP** A03:2021 · **CWE** CWE-89 · **Severity** critical

Building a SQL string via template literal or concatenation that includes `req.body`/`req.query`/`req.params` directly. Includes raw drivers (`pg`, `mysql2`), Knex `.raw`, Sequelize `.query`/`.literal`, TypeORM `.where("…${x}…")` on a query builder.

**Vulnerable**:
```ts
await pool.query(`SELECT * FROM users WHERE email = '${req.body.email}'`);
await knex.raw('SELECT * FROM products WHERE name LIKE ' + "'%" + req.query.q + "%'");
await sequelize.query(`UPDATE accounts SET balance = ${req.body.amount} WHERE id = ${req.params.id}`);
await repo.createQueryBuilder('u').where(`u.role = '${req.body.role}'`).getMany();
```

**Safe**:
```ts
await pool.query('SELECT * FROM users WHERE email = $1', [req.body.email]);
await knex('products').where('name', 'like', `%${req.query.q}%`);                 // query builder
await sequelize.query('UPDATE accounts SET balance = :amount WHERE id = :id', { replacements: { amount: req.body.amount, id: req.params.id } });
await repo.createQueryBuilder('u').where('u.role = :role', { role: req.body.role }).getMany();
```

**Confidence guidance**: template literal with `${…}` containing `req.*` is high-confidence TP. String concatenation `'… ' + x + ' …'` where `x` is user-typed is TP. Parameterized queries with `?` or `$1` placeholders are safe.

**Fix**: always use parameter binding. Where a string really must be interpolated (table name, column name from allowlist), validate it against a strict set before splicing.

**Reference**: <https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html>

---

## B-02 — Command injection via `child_process` with user input

**OWASP** A03:2021 · **CWE** CWE-78 · **Severity** critical

`exec`, `execSync`, `spawn`, `spawnSync`, `execFile`, `execFileSync` invoked with a shell command that interpolates `req.*` or `process.argv`. Even `spawn` with `shell: true` re-introduces the shell.

**Vulnerable**:
```ts
exec(`convert ${req.body.input} out.png`);
execSync('rm -rf ' + req.params.path);
spawn('sh', ['-c', `git clone ${req.body.repo}`]);
```

**Safe**:
```ts
execFile('convert', [req.body.input, 'out.png']);            // arg array, no shell
const r = spawn('git', ['clone', req.body.repo], { shell: false });
// Validate paths/inputs first too:
if (!/^[a-zA-Z0-9._-]+$/.test(req.body.input)) return res.status(400).end();
```

**Confidence guidance**: any non-literal first argument to `exec`/`execSync` is high-risk. `execFile`/`spawn` with literal binary + array of args (no `shell: true`) is safe.

**Fix**: use `execFile`/`spawn` with argument arrays; validate input against strict allowlist; never use `exec` for user-tainted commands.

**Reference**: <https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html>

---

## B-03 — NoSQL injection (Mongoose `$where`, untrusted operators)

**OWASP** A03:2021 · **CWE** CWE-943 · **Severity** high

MongoDB-style queries where a filter object is built directly from `req.body` or `req.query` lets the attacker inject operators like `{$gt: ''}` (matches anything) or `{$where: 'function() { return true }'}` (JS execution on the DB).

**Vulnerable**:
```ts
const user = await User.findOne(req.body);                            // attacker: {email:{$gt:''}, password:{$gt:''}}
const items = await db.collection('items').find({ $where: req.body.code });
await User.updateOne(req.body.filter, req.body.update);
```

**Safe**:
```ts
const user = await User.findOne({ email: String(req.body.email) }).select('+passwordHash');
const valid = await bcrypt.compare(req.body.password, user.passwordHash);
// Or use a validator (zod, joi, class-validator) to strip operators:
const safe = z.object({ email: z.string().email() }).parse(req.body);
const user2 = await User.findOne(safe);
```

**Confidence guidance**: passing whole `req.body` or `req.query` as a filter is TP. Passing individual fields after type coercion or schema validation is safe.

**Fix**: validate input shape with a schema; coerce primitives; never accept operator-containing objects from clients.

**Reference**: <https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet_in_Java.html#nosql-injection>

---

## B-04 — Server-Side Request Forgery (SSRF)

**OWASP** A10:2021 · **CWE** CWE-918 · **Severity** high

Any outbound HTTP call (`fetch`, `axios`, `got`, `superagent`, `needle`, `phin`, `node-fetch`, `undici.fetch/request`, `http.get`, `http.request`, `https.get`, `https.request`) where the URL is derived from `req.body|query|params`. Lets the attacker probe internal networks, cloud metadata (169.254.169.254), or unauthenticated admin panels via the server's IP.

**Vulnerable**:
```ts
app.post('/preview', async (req, res) => {
  const r = await axios.get(req.body.url);
  res.json({ html: r.data });
});
await fetch(req.query.target as string);
await got(req.body.callback);
```

**Safe**:
```ts
const ALLOWED = new Set(['api.partner.com', 'cdn.example.com']);
const url = new URL(req.body.url);
if (!ALLOWED.has(url.host) || url.protocol !== 'https:') return res.status(400).end();
const r = await axios.get(url.toString(), { timeout: 3000 });
// Or use a server-side allowlist proxy.
```

**Confidence guidance**: any HTTP client called with a URL derived from `req.*` is high-confidence TP. Hardcoded URLs or env-derived URLs are safe. Allowlist-validated URLs are safe.

**Fix**: enforce an explicit allowlist of target hosts; restrict to `https:`; block private/loopback IP ranges (10/8, 127/8, 169.254/16, 192.168/16, ::1, fc00::/7).

**Reference**: <https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html>

---

## B-05 — Path traversal in `fs.*`

**OWASP** A01:2021 · **CWE** CWE-22 · **Severity** high

`fs.readFile`, `fs.writeFile`, `fs.createReadStream`, `fs.unlink`, etc. called with a path derived from `req.body|query|params` lets the attacker read/write files outside the intended directory via `../` sequences.

**Vulnerable**:
```ts
app.get('/file/:name', (req, res) => {
  res.sendFile(`/var/data/${req.params.name}`);              // ?name=../../../etc/passwd
});
await fs.readFile(path.join('/uploads', req.query.file));
await fs.unlink(req.body.path);
```

**Safe**:
```ts
const base = path.resolve('/var/data');
const target = path.resolve(base, path.basename(req.params.name));
if (!target.startsWith(base + path.sep)) return res.status(400).end();
res.sendFile(target);
```

**Confidence guidance**: file paths from `req.*` without `path.resolve` + boundary check are TP. Paths from env vars or hardcoded literals are safe. `path.basename(req.x)` alone helps but isn't sufficient (Windows separators, absolute paths).

**Fix**: resolve the target path, assert it stays inside the allowed root, and reject otherwise. Prefer fixed identifiers (UUIDs) as a lookup key into a DB rather than letting users name files directly.

**Reference**: <https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html>

---

## B-06 — Unsafe deserialization / dynamic code execution

**OWASP** A08:2021 · **CWE** CWE-502 · **Severity** critical

`eval(x)`, `new Function(x)`, `vm.runInThisContext`, `vm.runInNewContext`, `node-serialize.unserialize` invoked with user-controlled input. RCE on the server.

**Vulnerable**:
```ts
eval(req.body.code);
const fn = new Function('payload', req.body.fn);
vm.runInNewContext(req.body.script, sandbox);
const obj = unserialize(req.body.data);                      // node-serialize is famous for __js_function RCE
```

**Safe**:
```ts
// Just don't. If you need user-defined formulas, use a safe expression evaluator
// like expr-eval, mathjs, or a domain-specific interpreter you control.
// For deserialization, use JSON.parse with a schema validator.
const data = z.object({ name: z.string(), amount: z.number() }).parse(JSON.parse(req.body.data));
```

**Confidence guidance**: `eval`/`new Function` with non-literal first argument is unconditionally TP. `vm.run*` is TP. JSON.parse alone is fine (no code execution). `node-serialize.unserialize` is critical TP.

**Fix**: avoid dynamic code execution entirely; use a sandboxed evaluator with whitelisted operators; deserialize via JSON + schema.

**Reference**: <https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html>

---

## B-07 — Weak crypto (MD5/SHA1 for passwords, hardcoded JWT secret)

**OWASP** A02:2021 · **CWE** CWE-327 · **Severity** high

Two related patterns: (a) hashing passwords with `crypto.createHash('md5'|'sha1')` — fast hashes are bruteforceable; passwords need bcrypt/argon2/scrypt. (b) `jwt.sign(payload, 'some-hardcoded-string', ...)` puts the signing key in source.

**Vulnerable**:
```ts
const hash = crypto.createHash('md5').update(password).digest('hex');
const token = jwt.sign({ uid }, 'mysecret123', { expiresIn: '7d' });
```

**Safe**:
```ts
const hash = await bcrypt.hash(password, 12);                                   // or argon2
const token = jwt.sign({ uid }, process.env.JWT_SECRET!, { expiresIn: '7d' });
```

**Confidence guidance**: `createHash('md5'|'sha1')` for password-shaped data is TP. The same hashes for file integrity (checksum, ETag) are FP — md5/sha1 are still acceptable for non-cryptographic identification. JWT secret as a non-empty literal is TP; empty string or env-derived is safe.

**Fix**: use bcrypt (≥cost 12), argon2id, or scrypt for passwords; load JWT secrets from env / KMS.

**Reference**: <https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html>

---

## B-08 — Missing CSRF protection on state-changing route

**OWASP** A01:2021 · **CWE** CWE-352 · **Severity** medium

Express POST/PUT/DELETE/PATCH routes that don't reference CSRF middleware (csurf, csrf-csrf, double-csrf) **when the app uses cookie-based session auth**. Cookie-only auth = browser auto-sends credentials on cross-origin requests; without CSRF token, attacker can forge state-changing requests via a CSRF page on another origin.

**Vulnerable** (when cookie sessions are in use):
```ts
app.use(session({ secret: process.env.S, cookie: { httpOnly: true } }));

app.post('/transfer', (req, res) => {                       // no CSRF check
  transfer(req.session.user, req.body.to, req.body.amount);
  res.json({ ok: true });
});
```

**Safe**:
```ts
app.use(session({ ... }));
app.use(csurf());

app.post('/transfer', (req, res) => {
  // csurf verifies req.body._csrf or X-CSRF-Token header
  transfer(req.session.user, req.body.to, req.body.amount);
  res.json({ ok: true });
});
// Or: pure token-bearer APIs (Authorization: Bearer) don't need CSRF — same-site doesn't auto-send Authorization.
```

**Confidence guidance**: only flag if the diff shows cookie-session usage (`express-session`, `cookie-session`) AND new state-changing routes without CSRF middleware. APIs that authenticate via `Authorization: Bearer ...` don't need CSRF protection. If middleware setup is in a different file not in the diff, prefer `NEEDS_HUMAN`.

**Fix**: add `csurf()` / `doubleCsrfProtection()` to the relevant router; or move to token-bearer auth.

**Reference**: <https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html>

---

## B-09 — Missing Helmet middleware on Express app

**OWASP** A05:2021 · **CWE** CWE-693 · **Severity** medium

An Express app initialized with `express()` and route handlers but no `helmet()` middleware ships with default Express headers — missing CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy. Defense-in-depth gap.

**Vulnerable**:
```ts
import express from 'express';
const app = express();
app.use(express.json());
app.get('/api/me', ...);
app.listen(3000);                                            // no helmet
```

**Safe**:
```ts
import express from 'express';
import helmet from 'helmet';

const app = express();
app.use(helmet());                                           // or helmet({ contentSecurityPolicy: { directives: {...} } })
app.use(express.json());
app.get('/api/me', ...);
app.listen(3000);
```

**Confidence guidance**: only flag if the diff adds Express app initialization without `helmet` (import + `app.use(helmet())`). If middleware is set up in a separate file we can't see, prefer `NEEDS_HUMAN`. Skip test files.

**Fix**: `npm i helmet && app.use(helmet())` near the top of the middleware stack.

**Reference**: <https://helmetjs.github.io/>

---

## B-10 — Hardcoded credentials in connection string

**OWASP** A07:2021 · **CWE** CWE-798 · **Severity** critical

Connection URIs like `postgres://user:password@host/db`, `mongodb://...`, `mysql://...`, `redis://...`, `amqp://...` with inline passwords in source. Same risk as R-07 but in a recognizable URL form.

**Vulnerable**:
```ts
const pool = new Pool({ connectionString: 'postgres://app:s3cretP@ssw0rd@db.example.com/prod' });
const mongo = mongoose.connect('mongodb+srv://admin:Adm1nP@ss@cluster0.abc.mongodb.net/app');
```

**Safe**:
```ts
const pool = new Pool({ connectionString: process.env.DATABASE_URL });
await mongoose.connect(process.env.MONGO_URI!);
```

**Confidence guidance**: URI literals containing `:password@` with 4+ char password are TP. Localhost test fixtures (`postgres://test:test@localhost`) are FP. Template literals interpolating env are safe.

**Fix**: rotate the leaked credential; load from env or secret manager.

**Reference**: <https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html>

---

## B-11 — IDOR (Insecure Direct Object Reference)

**OWASP** A01:2021 · **CWE** CWE-639 · **Severity** high

`Model.findById(req.params.id)`, `Model.findByPk(req.body.id)`, `Model.findOne({ where: { id: req.query.id } })`, `prisma.x.findUnique({ where: { id } })` without a subsequent ownership check (`req.user.id === record.userId`) lets any authenticated user load any object by ID.

**Vulnerable**:
```ts
app.get('/orders/:id', async (req, res) => {
  const order = await Order.findById(req.params.id);
  res.json(order);                                            // any user can read any order
});
```

**Safe**:
```ts
app.get('/orders/:id', async (req, res) => {
  const order = await Order.findById(req.params.id);
  if (!order || order.userId !== req.user.id) return res.status(403).end();
  res.json(order);
});
// Or push the check into the query:
const order = await Order.findOne({ where: { id: req.params.id, userId: req.user.id } });
```

**Confidence guidance**: lookup by user-supplied id with no visible authz check is `LIKELY_TP`. If middleware-level authz exists in a different file (`requireOwnership`), prefer `NEEDS_HUMAN`. Public endpoints (lookup by slug, read-only public data) are safe.

**Fix**: add ownership check inside handler or in shared middleware; bake the user filter into the query.

**Reference**: <https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html>

---

## B-12 — XXE (XML External Entity)

**OWASP** A05:2021 · **CWE** CWE-611 · **Severity** high

XML parsers like `libxmljs`/`libxmljs2` with default options process external entities — attacker XML can read server files (`/etc/passwd`), make SSRF requests, or trigger billion-laughs DoS.

**Vulnerable**:
```ts
const doc = libxmljs.parseXml(req.body.xml);                  // defaults allow entities
const doc2 = libxmljs2.parseXmlString(payload);
parseString(req.body.xml, (err, result) => { /* xml2js, defaults */ });
```

**Safe**:
```ts
const doc = libxmljs.parseXml(req.body.xml, { noent: false, nonet: true, noblanks: true });
// xml2js is safer by default (no entity expansion) but still validate:
const parser = new xml2js.Parser({ explicitArray: false, explicitRoot: false });
const result = await parser.parseStringPromise(req.body.xml);
```

**Confidence guidance**: libxmljs* parsing without explicit `{noent: false, nonet: true}` options is high TP. xml2js is medium — its defaults are mostly safe but still recommend validation. `sax` parser (event-driven) is generally safe.

**Fix**: disable entity expansion and network access in the parser options; or move to JSON.

**Reference**: <https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html>

---

## B-13 — Mass assignment

**OWASP** A08:2021 · **CWE** CWE-915 · **Severity** high

ORM updates / creates that splat `req.body` into a model. The attacker can set fields they shouldn't — `role: 'admin'`, `isVerified: true`, `creditBalance: 999999`.

**Vulnerable**:
```ts
await User.update(req.body, { where: { id: req.user.id } });        // includes role, status, …
const user = new User({ ...req.body });
Object.assign(existingUser, req.body);
await Account.create(req.body);
```

**Safe**:
```ts
const { name, email, bio } = req.body;
await User.update({ name, email, bio }, { where: { id: req.user.id } });
// Or use a DTO / schema validator that strips disallowed fields:
const safe = z.object({ name: z.string(), email: z.string().email() }).parse(req.body);
await User.update(safe, { where: { id: req.user.id } });
```

**Confidence guidance**: `Model.update|create|save(req.body)` is TP. `Object.assign({}, req.body)` is prototype pollution (R-05), not mass assignment. Explicit field destructuring is safe.

**Fix**: whitelist allowed fields with explicit destructuring or schema validation; never trust the full body shape.

**Reference**: <https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html>

---

## B-14 — Server-side open redirect

**OWASP** A01:2021 · **CWE** CWE-601 · **Severity** medium

`res.redirect(req.query.next)`, `res.location(req.body.target)`, including the 2-arg form `res.redirect(302, target)`. Same phishing risk as R-08 but server-side.

**Vulnerable**:
```ts
app.get('/login', (req, res) => {
  // ...login logic...
  res.redirect(req.query.next as string);                     // ?next=https://evil.com
});
res.redirect(302, req.body.returnTo);
res.location(req.params.target).status(303).end();
```

**Safe**:
```ts
const ALLOW = new Set(['/dashboard', '/settings', '/home']);
const next = String(req.query.next || '/dashboard');
res.redirect(ALLOW.has(next) ? next : '/dashboard');
// Or only allow relative paths:
res.redirect(next.startsWith('/') && !next.startsWith('//') ? next : '/dashboard');
```

**Confidence guidance**: `res.redirect(req.X)` is TP. Hardcoded redirect targets are safe. HMAC-signed tokens in the URL parameter validate the redirect intent.

**Fix**: allowlist target paths or hosts; relative-URL-only; HMAC-signed tokens.

**Reference**: <https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html>

---

## B-15 — Server-side template injection (SSTI)

**OWASP** A03:2021 · **CWE** CWE-94 · **Severity** critical

`res.render(req.body.template)` lets the attacker pick the template — including path-traversal into other templates or invoking templates with side effects. Worse: `pug.compile(req.body.tpl)`, `handlebars.compile(req.X)`, `ejs.render(req.body.template)`, `mustache.render(req.X)` — the attacker can supply the *template body* and execute server-side JS via constructs like `{{constructor.constructor('return process')()}}`.

**Vulnerable**:
```ts
res.render(req.body.template, { user: req.user });
const fn = pug.compile(req.body.tpl);
const out = ejs.render(req.body.template, { items });
const html = Handlebars.compile(req.query.template as string)({ user: req.user });
```

**Safe**:
```ts
res.render('profile', { user: req.user });                   // fixed template name
const fn = pug.compileFile(path.join(__dirname, 'views', 'profile.pug'));
const out = ejs.render(STATIC_TEMPLATE, { items });
```

**Confidence guidance**: any template engine `compile`/`render`/`renderFile`/`renderString` with first arg from `req.*` is critical TP. `res.render` with non-literal template name is TP.

**Fix**: render only from a fixed set of templates; never accept template body or template name from a client.

**Reference**: <https://portswigger.net/web-security/server-side-template-injection>

---

# Container rules (D-XX)

## D-01 — Container runs as root

**OWASP** A05:2021 · **CWE** CWE-250 · **Severity** high

A Dockerfile without a `USER` directive (or with `USER root`/`USER 0`) runs the entrypoint as root inside the container. An RCE in the application then has full filesystem access inside the container, can mutate the image, and is one kernel exploit away from host escape.

**Vulnerable**:
```dockerfile
FROM node:20-alpine
WORKDIR /app
COPY . .
RUN npm ci --omit=dev
CMD ["node", "server.js"]
# No USER — runs as root
```

**Safe**:
```dockerfile
FROM node:20-alpine
WORKDIR /app
COPY . .
RUN npm ci --omit=dev
USER node                                                    # built-in non-root user on official Node images
CMD ["node", "server.js"]
```

**Confidence guidance**: missing `USER` is high TP. `USER 1000` (or any non-zero numeric/named user) is safe. Multi-stage builds need the final stage to set USER.

**Fix**: add `USER <non-root>` before CMD/ENTRYPOINT. On Node official images, `USER node` is pre-created.

**Reference**: <https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html#rule-2---set-a-user>

---

## D-02 — Mutable `latest` tag in FROM

**OWASP** A06:2021 · **CWE** CWE-1104 · **Severity** medium

`FROM node:latest`, `FROM postgres:latest`, or `FROM ubuntu` (which defaults to `:latest`) — build output is not reproducible, and a malicious upstream tag swap silently ships compromised binaries.

**Vulnerable**:
```dockerfile
FROM node:latest
FROM nginx
```

**Safe**:
```dockerfile
FROM node:20.11.1-alpine
# Or pin by digest for absolute reproducibility:
FROM node@sha256:a8e...
```

**Confidence guidance**: explicit `:latest` is TP. Missing tag (implicit `:latest`) is TP. Pinned numeric tags (`:20`, `:20.11`, `:20.11.1`) are safe — `:20` is loose but still better than `latest`. Digest pin is best.

**Fix**: pin to a specific version tag, or use `image@sha256:...` digest.

**Reference**: <https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html#rule-4---use-multi-stage-builds>

---

## D-03 — Hardcoded secret in Dockerfile ENV/ARG

**OWASP** A07:2021 · **CWE** CWE-798 · **Severity** critical

`ENV API_KEY=sk_live_...`, `ARG DB_PASSWORD=secret123`. These bake the secret into image layers — anyone with image access (registry pull, docker history) can extract them.

**Vulnerable**:
```dockerfile
ENV STRIPE_KEY=sk_live_51Hxxxxxxxxxxxxxxxxxxxxxx
ARG DB_PASSWORD=Adm1nP@ss
ENV JWT_SECRET=mysecret123
```

**Safe**:
```dockerfile
# Don't set the secret at build time. Set it at runtime via:
#   docker run -e STRIPE_KEY=... ...
# Or use docker secrets / k8s secrets:
ENV STRIPE_KEY=""   # placeholder, overridden at runtime
```

**Confidence guidance**: ENV/ARG with literal values that look like API keys, JWTs, or password strings are TP. Empty defaults (`ENV X=""`) and references like `ENV X=$SOMETHING` are safe.

**Fix**: pass secrets at runtime via env, docker secrets, or a secret manager — never bake them into images.

**Reference**: <https://docs.docker.com/build/building/secrets/>

---

## D-04 — `ADD` for local files instead of `COPY`

**OWASP** A05:2021 · **CWE** CWE-829 · **Severity** medium

`ADD` has side effects beyond `COPY`: auto-extracts tarballs, supports remote URLs. When used for plain local file copy, those side effects are unwanted — and an `ADD https://...` is unverified download into the image.

**Vulnerable**:
```dockerfile
ADD package.json /app/
ADD https://example.com/installer.sh /tmp/
ADD some.tar.gz /opt/                                        # auto-extracts
```

**Safe**:
```dockerfile
COPY package.json /app/
# For remote files, fetch + verify checksum:
RUN curl -fsSL https://example.com/installer.sh -o /tmp/installer.sh \
  && echo "<sha256>  /tmp/installer.sh" | sha256sum -c
# For tarballs you actually want extracted, ADD is OK but be deliberate.
```

**Confidence guidance**: `ADD <local-path>` for non-tarball local files is TP (use COPY). `ADD <url>` is TP unless followed by checksum verification. `ADD <tar>` for intentional auto-extract is FP.

**Fix**: prefer `COPY` for local files; for remote downloads, use `RUN curl ... && verify-checksum`.

**Reference**: <https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#add-or-copy>

---

## D-05 — `privileged: true` in docker-compose

**OWASP** A04:2021 · **CWE** CWE-250 · **Severity** high

`privileged: true` disables most container isolation — the container gets ALL kernel capabilities and direct device access. Effectively root on the host kernel namespace.

**Vulnerable**:
```yaml
services:
  app:
    image: myapp
    privileged: true
```

**Safe**:
```yaml
services:
  app:
    image: myapp
    cap_drop: [ALL]
    cap_add: [NET_BIND_SERVICE]   # only what's actually needed
    security_opt:
      - no-new-privileges:true
```

**Confidence guidance**: `privileged: true` is unconditional TP. The (rare) legitimate cases (docker-in-docker, hardware access) should be obvious in context.

**Fix**: drop `privileged`; add only the specific capabilities required via `cap_add`.

**Reference**: <https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities>

---

## D-06 — `network_mode: host` in docker-compose

**OWASP** A04:2021 · **CWE** CWE-668 · **Severity** high

`network_mode: host` shares the host's network namespace — the container can bind any host port, read host network traffic, and bypass docker network isolation entirely.

**Vulnerable**:
```yaml
services:
  app:
    image: myapp
    network_mode: host
```

**Safe**:
```yaml
services:
  app:
    image: myapp
    ports:
      - "127.0.0.1:3000:3000"     # explicit, bind to loopback only if internal
    networks:
      - backend
networks:
  backend:
    driver: bridge
```

**Confidence guidance**: `network_mode: host` is TP. `network_mode: bridge`/`none`/custom-network is safe. Default network is safe.

**Fix**: use bridge networking with explicit port mappings; if you really need host networking (e.g. for a network monitor), isolate via separate compose file.

**Reference**: <https://docs.docker.com/network/host/>

---

## D-07 — Mount of `/var/run/docker.sock`

**OWASP** A05:2021 · **CWE** CWE-732 · **Severity** critical

Mounting `/var/run/docker.sock` into a container gives that container root-equivalent control over the host's Docker daemon — it can launch new privileged containers, mount host paths, exfiltrate other containers' data. Effectively container escape by design.

**Vulnerable**:
```yaml
services:
  watchtower:
    image: containrrr/watchtower
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
```

**Safe**:
```yaml
# Don't mount the socket. If a workload truly needs Docker API access,
# run it on the host (not in a container), or use a socket proxy like
# tecnativa/docker-socket-proxy that limits API operations:
services:
  watchtower:
    image: containrrr/watchtower
    environment:
      - DOCKER_HOST=tcp://docker-proxy:2375
  docker-proxy:
    image: tecnativa/docker-socket-proxy
    environment:
      - CONTAINERS=1            # read-only container listing
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
```

**Confidence guidance**: any mount of `/var/run/docker.sock` is TP. Even read-only mounts grant significant capability — flag those as `LIKELY_TP`.

**Fix**: remove the mount; use a socket proxy with restricted permissions if API access is truly needed.

**Reference**: <https://docs.docker.com/engine/security/#docker-daemon-attack-surface>

---

## D-08 — Unsafe `apt-get install` (no `--no-install-recommends`, no version pinning)

**OWASP** A06:2021 · **CWE** CWE-1104 · **Severity** low

`RUN apt-get install -y curl` pulls latest versions of curl plus all "recommended" packages. Result: larger attack surface, non-reproducible builds.

**Vulnerable**:
```dockerfile
RUN apt-get update && apt-get install -y curl wget vim
```

**Safe**:
```dockerfile
RUN apt-get update \
  && apt-get install -y --no-install-recommends \
       curl=7.88.* \
       ca-certificates=20230311 \
  && rm -rf /var/lib/apt/lists/*
```

**Confidence guidance**: `apt-get install` without `--no-install-recommends` is TP-low. No version pinning is also TP-low. Combined → still low severity (defense-in-depth, not exploitable directly). Alpine `apk add --no-cache` is the equivalent best practice.

**Fix**: add `--no-install-recommends`; pin versions for reproducibility; clean apt lists after install.

**Reference**: <https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#apt-get>
