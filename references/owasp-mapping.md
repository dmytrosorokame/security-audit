# OWASP Top 10 (2021) → CWE → Frontend Manifestation

Цей документ — дзеркало стандарту OWASP Top 10 Web (2021) з фокусом на клієнтську частину. Для кожної категорії — короткий опис, ключові CWE, FE-маніфестації, відповідні правила (R-XX), і посилання на офіційні джерела.

---

## A01:2021 — Broken Access Control

**Опис**. Користувач може отримати доступ до даних/функцій поза дозволеним scope.

**FE-релевантні CWE**:
- CWE-601 — URL Redirection to Untrusted Site (open redirect)
- CWE-639 — Authorization Bypass Through User-Controlled Key
- CWE-862 — Missing Authorization (client-only checks)

**FE-маніфестації**:
- Лише FE-маска (`if (user.role !== 'admin') return null`) без BE-перевірки.
- `redirect=` параметри без allowlist (open redirect → R-08).
- Direct object references у URL/query без BE-валідації.

**Правила**: R-08.

**Source**: https://owasp.org/Top10/A01_2021-Broken_Access_Control/

---

## A02:2021 — Cryptographic Failures

**Опис**. Чутливі дані передаються/зберігаються без належного захисту.

**FE-релевантні CWE**:
- CWE-922 — Insecure Storage of Sensitive Information
- CWE-319 — Cleartext Transmission
- CWE-327 — Use of a Broken Crypto Algorithm

**FE-маніфестації**:
- JWT/refresh tokens у `localStorage` (R-06).
- Передача через `http://` замість `https://`.
- Кастомний crypto.subtle з небезпечним IV/режимом.

**Правила**: R-06.

**Source**: https://owasp.org/Top10/A02_2021-Cryptographic_Failures/

---

## A03:2021 — Injection

**Опис**. Недовірений input інтерпретується як код/команда.

**FE-релевантні CWE**:
- CWE-79 — Cross-Site Scripting (XSS)
- CWE-87 — Improper Neutralization of Alternate XSS Syntax

**FE-маніфестації**:
- DOM XSS через `innerHTML`, `dangerouslySetInnerHTML`, `document.write` (R-01, R-02).
- `javascript:` URL у `href`/`src` (R-04).
- Template injection у v-html (Vue), `[innerHTML]` (Angular).

**Правила**: R-01, R-02, R-04.

**Source**: https://owasp.org/Top10/A03_2021-Injection/

---

## A04:2021 — Insecure Design

**Опис**. Архітектурні дефекти, які не виправляються конфігом — потрібен redesign.

**FE-релевантні CWE**:
- CWE-346 — Origin Validation Error (postMessage)
- CWE-841 — Improper Enforcement of Behavioral Workflow

**FE-маніфестації**:
- `postMessage` без origin checks (R-09).
- Password reset через UI без rate limit / без BE-токенізації.
- "Trust the client" antipattern.

**Правила**: R-09.

**Source**: https://owasp.org/Top10/A04_2021-Insecure_Design/

---

## A05:2021 — Security Misconfiguration

**Опис**. Дефолтні/слабкі налаштування, відкриті директорії, відсутні security headers.

**FE-релевантні CWE**:
- CWE-693 — Protection Mechanism Failure (CSP, SRI)
- CWE-1022 — `target="_blank"` без `rel="noopener"`
- CWE-942 — Permissive CORS

**FE-маніфестації**:
- Відсутній CSP / SRI (R-10).
- target=_blank без noopener (R-03).
- CORS misconfig у клієнтських wrappers (R-11).
- Verbose error messages у production builds.

**Правила**: R-03, R-10, R-11.

**Source**: https://owasp.org/Top10/A05_2021-Security_Misconfiguration/

---

## A06:2021 — Vulnerable and Outdated Components

**Опис**. Залежності з відомими вразливостями.

**FE-релевантні CWE**:
- CWE-1395 — Dependency on Vulnerable Third-Party Component
- CWE-937 — OWASP Top 10 2013: Using Components with Known Vulnerabilities

**FE-маніфестації**:
- Прямі/transitive npm-залежності з активними CVE (R-12).
- Старі версії React/Apollo з відомими XSS-багами.
- CDN-скрипти без SRI (overlap з R-10).

**Правила**: R-12.

**Source**: https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/

---

## A07:2021 — Identification and Authentication Failures

**Опис**. Слабкі механізми ідентифікації/автентифікації.

**FE-релевантні CWE**:
- CWE-798 — Hard-coded Credentials
- CWE-287 — Improper Authentication
- CWE-384 — Session Fixation

**FE-маніфестації**:
- Hard-coded API keys / Bearer tokens у клієнтському bundle (R-07).
- Session ID у URL.
- Відсутність CSRF token у мутаціях.

**Правила**: R-07.

**Source**: https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/

---

## A08:2021 — Software and Data Integrity Failures

**Опис**. Довіра до коду/даних без перевірки цілісності.

**FE-релевантні CWE**:
- CWE-1321 — Prototype Pollution
- CWE-345 — Insufficient Verification of Data Authenticity

**FE-маніфестації**:
- Prototype pollution у `Object.assign`/recursive merge (R-05).
- Відсутність SRI на CDN-залежностях (overlap з R-10).
- Auto-update без signature verification.

**Правила**: R-05.

**Source**: https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/

---

## A09:2021 — Security Logging and Monitoring Failures

**Опис**. Недостатнє логування / моніторинг → пізнє виявлення інцидентів.

**FE-релевантність**: обмежена. На клієнті — telemetry на security events (CSP violations через `report-uri`, `Report-To` header). У scope скіла поки не входить.

**Source**: https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/

---

## A10:2021 — Server-Side Request Forgery (SSRF)

**Опис**. Сервер виконує запит на адресу, керовану атакером.

**BE-релевантні CWE**:
- CWE-918 — SSRF

**BE-маніфестації**:
- `fetch(req.body.url)`, `axios.get(req.query.target)` — Node-сервер виконує запит без allowlist (B-04).
- Доступ до cloud metadata (`169.254.169.254`) → крадіжка IAM credentials.

**Правила**: B-04.

**Source**: https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/

---

# Backend coverage (BE-rules)

Скіл також охоплює серверні маніфестації OWASP Top 10. Кожна BE-категорія має окрему секцію нижче (для full-stack аудиту).

## A03:2021 — Injection (BE)

- **CWE-89** — SQL injection incl. ORM raw queries / Sequelize.literal / TypeORM .where (B-01)
- **CWE-78** — OS Command Injection (B-02)
- **CWE-943** — NoSQL injection (B-03)
- **CWE-94** — Server-side template injection / SSTI (B-15)

## A01:2021 — Broken Access Control (BE)

- **CWE-22** — Path traversal (B-05)
- **CWE-352** — Cross-Site Request Forgery (B-08)
- **CWE-639** — IDOR (Insecure Direct Object Reference) (B-11)
- **CWE-601** — Server-side open redirect (B-14)

## A08:2021 — Software and Data Integrity Failures (BE)

- **CWE-502** — Deserialization of Untrusted Data (B-06)
- **CWE-915** — Mass assignment (B-13)

## A02:2021 — Cryptographic Failures (BE)

- **CWE-327** — Weak crypto algorithms (B-07)

## A05:2021 — Security Misconfiguration (BE)

- **CWE-693** — Missing security headers (B-09 — missing Helmet)
- **CWE-611** — XML External Entity / XXE (B-12)

## A07:2021 — Identification and Authentication Failures (BE)

- **CWE-798** — Hardcoded credentials у server-side connection strings (B-10)

## A10:2021 — SSRF (BE)

- **CWE-918** (B-04 — fetch/axios/got/superagent/http.request/etc. with user URL)

---

# Container / Deployment coverage (D-rules)

## A04:2021 — Insecure Design (Container)

- **CWE-250** — privileged container (D-05)
- **CWE-668** — network exposure (D-06)

## A05:2021 — Security Misconfiguration (Container)

- **CWE-250** — root user in container (D-01)
- **CWE-829** — ADD instead of COPY (D-04)
- **CWE-732** — docker.sock mount (D-07)

## A06:2021 — Vulnerable Components (Container)

- **CWE-1104** — `latest` tag (D-02), apt-get without pinning (D-08)

## A07:2021 — Identification & Auth Failures (Container)

- **CWE-798** — hardcoded secret in Dockerfile ENV (D-03)

---

## Summary Table

| OWASP | FE-coverage | BE-coverage | Container-coverage | Rules |
|-------|-------------|-------------|---------------------|-------|
| A01 | full (open redirect) | full (path traversal, CSRF, IDOR, SS-redirect) | n/a | R-08, B-05, B-08, B-11, B-14 |
| A02 | full (FE storage) | partial (weak crypto) | n/a | R-06, B-07 |
| A03 | full (DOM XSS) | full (SQLi+ORM, cmdi, NoSQLi, SSTI) | n/a | R-01, R-02, R-04, B-01, B-02, B-03, B-15 |
| A04 | partial (postMessage) | n/a | full (privileged, host net) | R-09, D-05, D-06 |
| A05 | full | full (Helmet, XXE) | full (root user, ADD, docker.sock) | R-03, R-10, R-11, B-09, B-12, D-01, D-04, D-07 |
| A06 | full (deps) | full (deps) | full (latest tag, apt unsafe) | R-12, D-02, D-08 |
| A07 | partial (hardcoded creds) | full (BE creds) | full (Dockerfile ENV) | R-07, B-10, D-03 |
| A08 | partial (proto pollution) | full (deserialization, mass-assignment) | n/a | R-05, B-06, B-13 |
| A09 | n/a | n/a | n/a | — |
| A10 | n/a | full (SSRF — all HTTP clients) | n/a | B-04 |
