# OWASP Top 10 (2021) → CWE → Frontend / Backend / Container Manifestation

This document mirrors the OWASP Top 10 Web (2021) standard with focus on how each category manifests in the code surface this skill audits (TS/JS/TSX/JSX + Dockerfile + docker-compose). For every category: a short description, the relevant CWEs, concrete manifestations, the matching rules (`R-XX` for frontend, `B-XX` for backend, `D-XX` for container), and a link to the official source.

---

## A01:2021 — Broken Access Control

**Summary.** A user can reach data or functionality outside their permitted scope.

**Relevant CWEs (frontend):**
- CWE-601 — URL redirection to untrusted site (open redirect)
- CWE-639 — Authorization bypass through user-controlled key
- CWE-862 — Missing authorization (client-only checks)

**Frontend manifestations:**
- Client-side gate only (`if (user.role !== 'admin') return null`) with no backend enforcement.
- `redirect=` query parameters without allowlist (open redirect → R-08).
- Direct object references in URL/query without backend validation.

**Rules:** R-08.

**Source:** https://owasp.org/Top10/A01_2021-Broken_Access_Control/

---

## A02:2021 — Cryptographic Failures

**Summary.** Sensitive data is transmitted or stored without adequate protection.

**Relevant CWEs (frontend):**
- CWE-922 — Insecure storage of sensitive information
- CWE-319 — Cleartext transmission
- CWE-327 — Use of a broken crypto algorithm

**Frontend manifestations:**
- JWT or refresh tokens in `localStorage` / `sessionStorage` (R-06).
- Transmission over `http://` instead of `https://`.
- Custom `crypto.subtle` usage with an unsafe IV or mode.

**Rules:** R-06.

**Source:** https://owasp.org/Top10/A02_2021-Cryptographic_Failures/

---

## A03:2021 — Injection

**Summary.** Untrusted input is interpreted as code or a command.

**Relevant CWEs (frontend):**
- CWE-79 — Cross-Site Scripting (XSS)
- CWE-87 — Improper neutralization of alternate XSS syntax

**Frontend manifestations:**
- DOM XSS via `dangerouslySetInnerHTML`, `innerHTML`, `document.write` (R-01, R-02).
- `javascript:` URL in `href` / `src` (R-04).
- Template injection via Vue's `v-html` or Angular's `[innerHTML]`.

**Rules:** R-01, R-02, R-04.

**Source:** https://owasp.org/Top10/A03_2021-Injection/

---

## A04:2021 — Insecure Design

**Summary.** Architectural defects that configuration alone cannot fix — they require a redesign.

**Relevant CWEs (frontend):**
- CWE-346 — Origin validation error (postMessage)
- CWE-841 — Improper enforcement of behavioral workflow

**Frontend manifestations:**
- `postMessage` without origin checks (R-09).
- Password reset UI flow without rate limiting or backend tokenisation.
- "Trust the client" antipattern.

**Rules:** R-09.

**Source:** https://owasp.org/Top10/A04_2021-Insecure_Design/

---

## A05:2021 — Security Misconfiguration

**Summary.** Default or weak settings, exposed directories, missing security headers.

**Relevant CWEs (frontend):**
- CWE-693 — Protection mechanism failure (CSP, SRI)
- CWE-1022 — `target="_blank"` without `rel="noopener"`
- CWE-942 — Permissive CORS

**Frontend manifestations:**
- Missing CSP / SRI (R-10).
- `target="_blank"` without `noopener` (R-03).
- CORS misconfiguration in client-side wrappers (R-11).
- Verbose error messages in production builds.

**Rules:** R-03, R-10, R-11.

**Source:** https://owasp.org/Top10/A05_2021-Security_Misconfiguration/

---

## A06:2021 — Vulnerable and Outdated Components

**Summary.** Dependencies with known vulnerabilities.

**Coverage note.** Dependency-CVE scanning is **out of scope** for this skill (use Dependabot, Snyk, or OSV-Scanner for that). The only adjacent rules this skill enforces are CDN scripts without SRI (R-10) and Docker base images with the mutable `:latest` tag (D-02).

**Source:** https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/

---

## A07:2021 — Identification and Authentication Failures

**Summary.** Weak identification or authentication mechanisms.

**Relevant CWEs (frontend):**
- CWE-798 — Use of hard-coded credentials
- CWE-287 — Improper authentication
- CWE-384 — Session fixation

**Frontend manifestations:**
- Hardcoded API keys or Bearer tokens in the client bundle (R-07).
- Session ID exposed in the URL.
- Missing CSRF token on mutating requests.

**Rules:** R-07.

**Source:** https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/

---

## A08:2021 — Software and Data Integrity Failures

**Summary.** Trusting code or data without integrity verification.

**Relevant CWEs (frontend):**
- CWE-1321 — Prototype pollution
- CWE-345 — Insufficient verification of data authenticity

**Frontend manifestations:**
- Prototype pollution via `Object.assign` / recursive merge (R-05).
- Missing SRI on CDN dependencies (overlaps with R-10).
- Auto-update mechanism without signature verification.

**Rules:** R-05.

**Source:** https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/

---

## A09:2021 — Security Logging and Monitoring Failures

**Summary.** Insufficient logging or monitoring leads to late incident detection.

**Frontend relevance:** limited. On the client this manifests as CSP-violation telemetry (`report-uri`, `Report-To` header). Not currently in the skill's scope — A09 is an operational concern, not a code-level one.

**Source:** https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/

---

## A10:2021 — Server-Side Request Forgery (SSRF)

**Summary.** The server makes a request to an attacker-controlled address.

**Relevant CWEs (backend):**
- CWE-918 — SSRF

**Backend manifestations:**
- `fetch(req.body.url)`, `axios.get(req.query.target)` — Node server issues a request without an allowlist (B-04).
- Access to cloud metadata (`169.254.169.254`) → IAM-credential theft.

**Rules:** B-04.

**Source:** https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/

---

# Backend coverage (B-rules)

The skill also covers server-side manifestations of the OWASP Top 10. Each backend category has its own grouping below for full-stack audits.

## A03:2021 — Injection (backend)

- **CWE-89** — SQL injection incl. ORM raw queries / `Sequelize.literal` / TypeORM raw `.where` (B-01)
- **CWE-78** — OS command injection (B-02)
- **CWE-943** — NoSQL injection (B-03)
- **CWE-94** — Server-side template injection / SSTI (B-15)

## A01:2021 — Broken Access Control (backend)

- **CWE-22** — Path traversal (B-05)
- **CWE-352** — Cross-Site Request Forgery (B-08)
- **CWE-639** — IDOR (Insecure Direct Object Reference) (B-11)
- **CWE-601** — Server-side open redirect (B-14)

## A08:2021 — Software and Data Integrity Failures (backend)

- **CWE-502** — Deserialization of untrusted data (B-06)
- **CWE-915** — Mass assignment (B-13)

## A02:2021 — Cryptographic Failures (backend)

- **CWE-327** — Weak crypto algorithms (B-07)

## A05:2021 — Security Misconfiguration (backend)

- **CWE-693** — Missing security headers (B-09 — missing Helmet)
- **CWE-611** — XML External Entity / XXE (B-12)

## A07:2021 — Identification and Authentication Failures (backend)

- **CWE-798** — Hardcoded credentials in server-side connection strings (B-10)

## A10:2021 — SSRF (backend)

- **CWE-918** — B-04 covers `fetch` / `axios` / `got` / `superagent` / `http.request` / etc. with a user-controlled URL.

---

# Container / deployment coverage (D-rules)

## A04:2021 — Insecure Design (container)

- **CWE-250** — Privileged container (D-05)
- **CWE-668** — Network exposure (D-06)

## A05:2021 — Security Misconfiguration (container)

- **CWE-250** — Container runs as root (D-01)
- **CWE-829** — `ADD` instead of `COPY` (D-04)
- **CWE-732** — `docker.sock` mount (D-07)

## A06:2021 — Vulnerable Components (container)

- **CWE-1104** — `latest` tag (D-02), `apt-get install` without version pinning (D-08)

## A07:2021 — Identification & Auth Failures (container)

- **CWE-798** — Hardcoded secret in Dockerfile `ENV` / `ARG` (D-03)

---

## Summary table

| OWASP | FE coverage | BE coverage | Container coverage | Rules |
|-------|-------------|-------------|--------------------|-------|
| A01 | full (open redirect) | full (path traversal, CSRF, IDOR, server-side redirect) | n/a | R-08, B-05, B-08, B-11, B-14 |
| A02 | full (FE storage) | partial (weak crypto) | n/a | R-06, B-07 |
| A03 | full (DOM XSS) | full (SQLi incl. ORM, cmdi, NoSQLi, SSTI) | n/a | R-01, R-02, R-04, B-01, B-02, B-03, B-15 |
| A04 | partial (postMessage) | n/a | full (privileged, host net) | R-09, D-05, D-06 |
| A05 | full | full (Helmet, XXE) | full (root user, `ADD`, `docker.sock`) | R-03, R-10, R-11, B-09, B-12, D-01, D-04, D-07 |
| A06 | out of scope (use Dependabot/Snyk) | out of scope | partial (`latest` tag, unsafe apt-get) | D-02, D-08 |
| A07 | partial (hardcoded creds in bundle) | full (BE creds) | full (Dockerfile `ENV`) | R-07, B-10, D-03 |
| A08 | partial (prototype pollution) | full (deserialization, mass assignment) | n/a | R-05, B-06, B-13 |
| A09 | n/a | n/a | n/a | — |
| A10 | n/a | full (SSRF — all HTTP clients) | n/a | B-04 |
