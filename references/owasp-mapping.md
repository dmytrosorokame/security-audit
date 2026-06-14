# OWASP Top 10 → CWE → Frontend / Backend / Container Manifestation

This document mirrors the OWASP Top 10 standard with focus on how each category manifests in the code surface this skill audits (TS/JS/TSX/JSX + Dockerfile + docker-compose). For every category: a short description, the relevant CWEs, concrete manifestations, the matching rules (`R-XX` for frontend, `B-XX` for backend, `D-XX` for container), and a link to the official source.

The category numbering and order in this document follow the current OWASP Top 10 standard (A01..A10). Note that the standard reorders and renames categories every release — when reading older write-ups, the mapping below also reflects how prior categories consolidated into the current taxonomy (e.g. SSRF, previously its own top-level category, is now treated as a specific form of Broken Access Control).

---

## A01 — Broken Access Control

**Summary.** A user can reach data or functionality outside their permitted scope. This category absorbs Server-Side Request Forgery: SSRF is treated as access-control failure on the trust boundary between an application and internal services.

**Relevant CWEs:**
- CWE-22 — Path traversal
- CWE-352 — Cross-Site Request Forgery
- CWE-601 — URL redirection to untrusted site (open redirect)
- CWE-639 — Authorization bypass through user-controlled key (IDOR)
- CWE-862 — Missing authorization
- CWE-918 — Server-Side Request Forgery (SSRF)

**Manifestations across the stack:**
- **Frontend:** client-only role gate without backend enforcement; `redirect=` query parameters without allowlist; direct object references in URL without backend validation (R-08).
- **Backend:** path traversal in file-loading routes (B-05); missing CSRF tokens on mutating endpoints (B-08); profile/order lookup by id without ownership check (B-11); SSRF via `fetch` / `axios` / `got` / `superagent` / `http.request` without an allowlist (B-04); missing function-level authorization on privileged/admin routes (B-19).

**Rules:** R-08, B-04, B-05, B-08, B-11, B-19.

**Source:** https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/

---

## A02 — Security Misconfiguration

**Summary.** Default or weak settings, exposed directories, missing security headers, overly permissive container/runtime configuration.

**Relevant CWEs:**
- CWE-250 — Execution with unnecessary privileges
- CWE-611 — XML External Entity (XXE)
- CWE-693 — Protection mechanism failure (CSP, SRI, Helmet)
- CWE-732 — Incorrect permission assignment
- CWE-829 — Inclusion of functionality from untrusted control sphere
- CWE-942 — Permissive CORS
- CWE-1022 — `target="_blank"` without `rel="noopener"`

**Manifestations across the stack:**
- **Frontend:** missing CSP / SRI (R-10); `target="_blank"` without `noopener` (R-03); CORS misconfiguration (R-11); verbose error messages in production builds.
- **Backend:** missing security headers / Helmet (B-09); XXE via misconfigured XML parser (B-12); ReDoS via nested-quantifier regex on user input (B-18); insecure session cookie flags / missing HttpOnly·Secure·SameSite (B-20).
- **Container:** root user inside container (D-01); `ADD` instead of `COPY` (D-04); `docker.sock` mounted into a service (D-07).

**Rules:** R-03, R-10, R-11, B-09, B-12, B-18, B-20, D-01, D-04, D-07.

**Source:** https://owasp.org/Top10/2025/A02_2025-Security_Misconfiguration/

---

## A03 — Software Supply Chain Failures

**Summary.** Risks arising from third-party packages, build infrastructure, distribution channels, and chain-of-custody of the artifacts a project consumes. Broader than the older "Vulnerable and Outdated Components" framing — covers build systems, signing, dependency resolution, and provenance.

**Coverage note.** Dependency-CVE scanning (resolution of installed versions against advisory databases) is **out of scope** for this skill (use Dependabot, Snyk, or OSV-Scanner). The adjacent rules this skill enforces in the diff are mutable container tags (`:latest`) and unpinned package installations.

**Relevant CWEs:**
- CWE-1104 — Use of unmaintained / unpinned third-party components

**Container manifestations:**
- `FROM image:latest` — mutable upstream image (D-02).
- `RUN apt-get install <pkg>` without `<pkg>=<version>` pin (D-08).

**Rules:** D-02, D-08.

**Source:** https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/

---

## A04 — Cryptographic Failures

**Summary.** Sensitive data is transmitted or stored without adequate protection. Includes hardcoded credentials embedded in code or env defaults, since they are a confidentiality failure of the credential storage layer.

**Relevant CWEs:**
- CWE-319 — Cleartext transmission
- CWE-327 — Use of a broken or risky cryptographic algorithm
- CWE-798 — Use of hard-coded credentials (when in a connection string / TLS context)
- CWE-916 — Password hashing with insufficient computational effort
- CWE-922 — Insecure storage of sensitive information

**Manifestations across the stack:**
- **Frontend:** JWT or refresh tokens in `localStorage` / `sessionStorage` (R-06); transmission over `http://`; custom `crypto.subtle` usage with an unsafe IV or mode.
- **Backend:** weak password hashing (MD5/SHA-1 instead of bcrypt/argon2) or `===` comparison on hashes (B-07); database / message-broker connection strings with embedded passwords (B-10); plaintext/unhashed password storage and comparison (B-21); JWT verified without an algorithm allowlist — alg:none / algorithm confusion (B-22).

**Rules:** R-06, B-07, B-10, B-21, B-22.

**Source:** https://owasp.org/Top10/2025/A04_2025-Cryptographic_Failures/

---

## A05 — Injection

**Summary.** Untrusted input is interpreted as code, query, command, or markup. Covers everything from DOM XSS through SQL injection to template-engine injection (SSTI). The decline in OWASP ranking reflects framework-level defaults (parameterised queries, JSX auto-escaping); the residual risk is in code that bypasses those defaults.

**Relevant CWEs:**
- CWE-78 — OS command injection
- CWE-79 — Cross-Site Scripting (XSS)
- CWE-87 — Improper neutralization of alternate XSS syntax
- CWE-89 — SQL injection
- CWE-94 — Code injection (template engines)
- CWE-601 — Server-side open redirect
- CWE-943 — NoSQL injection

**Manifestations across the stack:**
- **Frontend:** DOM XSS via `dangerouslySetInnerHTML`, `innerHTML`, `document.write` (R-01, R-02); `javascript:` URL in `href` / `src` (R-04); template injection via Vue's `v-html` or Angular's `[innerHTML]`.
- **Backend:** SQL injection including ORM raw queries / `Sequelize.literal` / TypeORM raw `.where` (B-01); OS command injection in `child_process.exec` (B-02); NoSQL injection via Mongoose `$where` (B-03); server-side template injection / SSTI (B-15); server-side open redirect via `res.redirect(req.query.next)` without allowlist (B-14).

**Rules:** R-01, R-02, R-04, B-01, B-02, B-03, B-14, B-15.

**Source:** https://owasp.org/Top10/2025/A05_2025-Injection/

---

## A06 — Insecure Design

**Summary.** Architectural defects that configuration alone cannot fix — they require a redesign. Often manifests as overly broad trust assumptions baked into module boundaries.

**Relevant CWEs:**
- CWE-250 — Execution with unnecessary privileges (architectural sibling of A02; appears here when the privilege escalation is by design rather than misconfiguration)
- CWE-346 — Origin validation error (`postMessage`)
- CWE-668 — Exposure of resource to wrong sphere
- CWE-841 — Improper enforcement of behavioral workflow

**Manifestations across the stack:**
- **Frontend:** `postMessage` without origin checks (R-09); password-reset UI flow without rate limiting or backend tokenisation; "trust the client" antipattern.
- **Container:** `privileged: true` on a compose service (D-05); host network namespace mount (D-06).

**Rules:** R-09, D-05, D-06.

**Source:** https://owasp.org/Top10/2025/A06_2025-Insecure_Design/

---

## A07 — Authentication Failures

**Summary.** Weak identification or authentication mechanisms — sessions, credentials, multi-factor flows.

**Relevant CWEs:**
- CWE-287 — Improper authentication
- CWE-384 — Session fixation
- CWE-798 — Use of hard-coded credentials (when the credential is an API key / token, not a TLS / crypto secret)

**Manifestations across the stack:**
- **Frontend:** hardcoded API keys or Bearer tokens shipped in the client bundle (R-07); session ID exposed in the URL.
- **Container:** hardcoded secret in Dockerfile `ENV` / `ARG` directive (D-03).

**Rules:** R-07, D-03.

**Source:** https://owasp.org/Top10/2025/A07_2025-Authentication_Failures/

---

## A08 — Software or Data Integrity Failures

**Summary.** Trusting code or data without integrity verification — auto-update without signature checks, prototype pollution that turns trusted helpers into attacker-controlled sinks, unsigned deserialisation.

**Relevant CWEs:**
- CWE-345 — Insufficient verification of data authenticity
- CWE-502 — Deserialization of untrusted data
- CWE-915 — Improperly controlled modification of dynamically-determined object attributes (mass assignment)
- CWE-1321 — Prototype pollution

**Manifestations across the stack:**
- **Frontend:** prototype pollution via `Object.assign` / recursive merge with attacker-controlled keys (R-05); missing SRI on CDN dependencies (overlaps with R-10); auto-update mechanism without signature verification.
- **Backend:** deserialization of untrusted data via `node-serialize`, YAML `!!js/function`, or unsafe `JSON.parse` reviver (B-06); mass assignment of request bodies into ORM models without an allowlist (B-13).

**Rules:** R-05, B-06, B-13.

**Source:** https://owasp.org/Top10/2025/A08_2025-Software_or_Data_Integrity_Failures/

---

## A09 — Logging and Alerting Failures

**Summary.** Insufficient logging or alerting leads to late incident detection. Adjacent code-level concern: verbose error responses that leak internal state and accelerate exploitation by the same attacker who triggered the error.

**Relevant CWEs:**
- CWE-209 — Generation of error message containing sensitive information (code-level, diff-observable)
- CWE-532 — Insertion of sensitive information into log file (mostly operational)
- CWE-778 — Insufficient logging (operational)

**Coverage note.** Partial coverage at the code level. The diff-observable subset (CWE-209: stack traces / error objects serialized into HTTP responses) is covered by **B-16**. The operational subset (CWE-778: missing SIEM, insufficient retention, alert routing) remains **out of scope** for diff review — use a dedicated observability stack (OpenTelemetry, Datadog, Grafana, Loki).

**Backend manifestations:**
- `res.send(err)` / `res.json({ error: err.stack })` / `res.status(500).send(e.message)` — leaks internals to the client (B-16).

**Rules:** B-16.

**Source:** https://owasp.org/Top10/2025/A09_2025-Security_Logging_and_Alerting_Failures/

---

## A10 — Mishandling of Exceptional Conditions

**Summary.** Error paths, partial failures, retries, and edge cases that are reached rarely in production but are decision points where security-relevant invariants can be bypassed (e.g. an exception swallowed in a permission check, or an open-fail default on identity verification).

**Relevant CWEs:**
- CWE-755 — Improper handling of exceptional conditions (diff-observable for structurally empty catch / unhandled rejections)
- CWE-754 — Improper check for unusual or exceptional conditions
- CWE-390 — Detection of error condition without action
- CWE-367 — TOCTOU race condition (out of scope: requires cross-file / runtime context)

**Coverage note.** Diff-observable patterns are covered by **B-17**: structurally empty `catch` blocks, missing `.catch()` on promises with external side effects, and stub `process.on('uncaughtException'|'unhandledRejection', () => {})` handlers. When the diff explicitly relaxes an error handler that previously enforced a security check (e.g. swallowing a thrown `ForbiddenError` inside an authz path), the finding is still emitted under the most specific applicable rule (B-11 for an authz bypass, B-04 for a fallback fetch, etc.) — the B-17 detection complements rather than replaces those category-specific rules.

Semantic race conditions (TOCTOU / CWE-367) and protocol-level exceptional handling (e.g. retry storms, partial commit rollback) remain out of scope as they require cross-file or runtime context unavailable to a diff-only analyser.

**Backend manifestations:**
- `try { ... } catch (_) {}` with no log / metric / intent-comment (B-17).
- `promise.then(handler)` without `.catch(...)` when the promise has external side effects (B-17).
- `process.on('uncaughtException', () => {})` empty handler — crashes hidden (B-17).

**Rules:** B-17.

**Source:** https://owasp.org/Top10/2025/A10_2025-Mishandling_of_Exceptional_Conditions/

---

## Summary table

| OWASP | FE coverage | BE coverage | Container coverage | Rules |
|-------|-------------|-------------|--------------------|-------|
| A01 Broken Access Control | partial (open redirect) | full (path traversal, CSRF, IDOR, SSRF) | n/a | R-08, B-04, B-05, B-08, B-11, B-19 |
| A02 Security Misconfiguration | full (CSP, SRI, CORS, tabnabbing) | full (Helmet, XXE) | full (root user, `ADD`, `docker.sock`) | R-03, R-10, R-11, B-09, B-12, B-18, B-20, D-01, D-04, D-07 |
| A03 Software Supply Chain Failures | out of scope (use Dependabot/Snyk) | out of scope | partial (`latest` tag, unsafe apt-get) | D-02, D-08 |
| A04 Cryptographic Failures | partial (insecure storage) | partial (weak crypto, hardcoded creds) | n/a | R-06, B-07, B-10, B-21, B-22 |
| A05 Injection | full (DOM XSS) | full (SQLi incl. ORM, cmdi, NoSQLi, SSTI, server-side open redirect) | n/a | R-01, R-02, R-04, B-01, B-02, B-03, B-14, B-15 |
| A06 Insecure Design | partial (postMessage) | n/a | full (privileged, host net) | R-09, D-05, D-06 |
| A07 Authentication Failures | partial (hardcoded creds in bundle) | n/a | full (Dockerfile `ENV`) | R-07, D-03 |
| A08 Software or Data Integrity Failures | partial (prototype pollution) | full (deserialization, mass assignment) | n/a | R-05, B-06, B-13 |
| A09 Logging and Alerting Failures | n/a | partial (verbose error / stack trace exposure) | n/a | B-16 |
| A10 Mishandling of Exceptional Conditions | n/a | partial (empty catch, missing `.catch()`, stub handlers) | n/a | B-17 |
