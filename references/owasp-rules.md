# Vulnerability Pattern Catalog — LLM Grounding for Diff Review

This catalog describes the **35 vulnerability patterns** the LLM agent looks for when reviewing diffs. Each pattern has: OWASP Top 10 (2021) category, CWE ID, severity, structural signature (how the pattern looks in code — useful as a recognition hint), false-positive guards, and remediation guidance with OWASP Cheat Sheet links.

**How the LLM uses this**: when analyzing a diff, the agent grounds its reasoning in this catalog. If a diff matches a `rule_id` pattern, the finding inherits the canonical `owasp_id`, `cwe_id`, `severity`. If a pattern is recognized but doesn't fit any catalog entry, the agent uses `rule_id: NEW_PATTERN` and flags for human review.

**Coverage**: 12 frontend (`R-XX`), 15 backend (`B-XX`), 8 container (`D-XX`) — 35 total. Each rule has structural signatures kept for LLM recognition.

## FE rules (R-XX)

| ID | Назва | OWASP | CWE | Severity |
|----|-------|-------|-----|----------|
| R-01 | DOM XSS via `dangerouslySetInnerHTML` без санітизації | A03:2021 | CWE-79 | high |
| R-02 | DOM XSS via `innerHTML`/`outerHTML`/`document.write` із зовнішнім input | A03:2021 | CWE-79 | high |
| R-03 | `<a target="_blank">` без `rel="noopener noreferrer"` | A05:2021 | CWE-1022 | medium |
| R-04 | `javascript:` URL у `href`/`src` | A03:2021 | CWE-79 | high |
| R-05 | Prototype pollution patterns (`Object.assign({}, untrusted)`, рекурсивний merge) | A08:2021 | CWE-1321 | high |
| R-06 | Зберігання токенів/секретів у `localStorage`/`sessionStorage` | A02:2021 | CWE-922 | high |
| R-07 | Hard-coded secrets/API keys у клієнтському коді | A07:2021 | CWE-798 | critical |
| R-08 | Open redirect через `window.location = userInput` | A01:2021 | CWE-601 | high |
| R-09 | `postMessage` без перевірки `origin` | A04:2021 | CWE-346 | high |
| R-10 | Відсутній CSP / SRI у HTML/Vite-конфігах | A05:2021 | CWE-693 | medium |
| R-11 | CORS misconfig (`Access-Control-Allow-Origin: *` з credentials) у клієнтських wrappers | A05:2021 | CWE-942 | high |
| R-12 | Залежності з відомими CVE (через `pnpm audit`) | A06:2021 | CWE-1395 | varies |

## BE rules (B-XX)

| ID | Назва | OWASP | CWE | Severity |
|----|-------|-------|-----|----------|
| B-01 | SQL injection через raw query з template literal/concat (Sequelize, Knex, pg/mysql) | A03:2021 | CWE-89 | critical |
| B-02 | Command injection через `child_process` з user input | A03:2021 | CWE-78 | critical |
| B-03 | NoSQL injection (Mongoose `$where`, raw `req.body` як filter) | A03:2021 | CWE-943 | high |
| B-04 | Server-side request forgery (SSRF) — fetch/axios з user-controlled URL | A10:2021 | CWE-918 | high |
| B-05 | Path traversal у `fs.*` з user input без `path.resolve/normalize` | A01:2021 | CWE-22 | high |
| B-06 | Unsafe deserialization (`eval`, `vm.run*`, `node-serialize`, `new Function(input)`) | A08:2021 | CWE-502 | critical |
| B-07 | Weak crypto (`md5`/`sha1` для паролів; hardcoded JWT secret) | A02:2021 | CWE-327 | high |
| B-08 | Express POST/PUT/DELETE/PATCH route без CSRF-middleware | A01:2021 | CWE-352 | medium |
| B-09 | Express застосунок без `helmet()` middleware | A05:2021 | CWE-693 | medium |
| B-10 | Server-side hardcoded credentials у connection-string (postgres/mongodb/mysql/...) | A07:2021 | CWE-798 | critical |

## Docker / Container rules (D-XX)

| ID | Назва | OWASP | CWE | Severity |
|----|-------|-------|-----|----------|
| D-01 | Container runs as root (no `USER` directive) | A05:2021 | CWE-250 | high |
| D-02 | Use of mutable `latest` tag у `FROM` | A06:2021 | CWE-1104 | medium |
| D-03 | Hardcoded secret у Dockerfile `ENV`/`ARG` | A07:2021 | CWE-798 | critical |
| D-04 | `ADD` для local files замість `COPY` | A05:2021 | CWE-829 | medium |
| D-05 | `privileged: true` у docker-compose | A04:2021 | CWE-250 | high |
| D-06 | `network_mode: host` у docker-compose | A04:2021 | CWE-668 | high |
| D-07 | Mount of `/var/run/docker.sock` (container escape) | A05:2021 | CWE-732 | critical |
| D-08 | `apt-get install` без `--no-install-recommends` і без version pinning | A06:2021 | CWE-1104 | low |

---

## R-01 — `dangerouslySetInnerHTML` без санітизації

**OWASP**: A03:2021 (Injection) **CWE**: CWE-79 (Improper Neutralization of Input During Web Page Generation)

**Опис**. React-проп `dangerouslySetInnerHTML={{__html: x}}` рендерить рядок як HTML без екранування. Якщо `x` містить недовірений input (URL-параметр, GraphQL response, user-generated content) і не пропущений через санітайзер — DOM XSS.

**AST-сигнатура** (TypeScript Compiler API):
- `JsxAttribute.name.escapedText === 'dangerouslySetInnerHTML'`
- value — `JsxExpression` containing object literal з ключем `__html`
- значення `__html` — НЕ literal string; не виклик `DOMPurify.sanitize(...)`/`sanitizeHtml(...)`

**False positive guard**. Якщо джерело — `import` з constants або статичний літерал → `confidence: low`, FP-likely.

**Remediation**. Використати `DOMPurify.sanitize(html, {ALLOWED_TAGS:[...]})` або відмовитись від HTML-рендеру на користь markdown-парсера з allowlist.

**OWASP Cheat Sheet**: https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html

---

## R-02 — `innerHTML` / `outerHTML` / `document.write` із зовнішнім input

**OWASP**: A03:2021 **CWE**: CWE-79

**Опис**. Прямий запис у DOM через `el.innerHTML = x`, `outerHTML`, `document.write(x)`, `insertAdjacentHTML(pos, x)` — XSS, якщо `x` неперевірений.

**AST-сигнатура**:
- `BinaryExpression` з `left.name === 'innerHTML' | 'outerHTML'` і operator `=`
- `CallExpression` з `expression === 'document.write' | 'document.writeln'`
- `CallExpression` з callee `insertAdjacentHTML`

**False positive guard**. Праве значення — string literal без template substitutions → FP.

**Remediation**. `textContent` для тексту; `DOMPurify.sanitize` + `innerHTML` тільки якщо HTML-рендер реально потрібен.

---

## R-03 — `<a target="_blank">` без `rel="noopener noreferrer"`

**OWASP**: A05:2021 (Security Misconfiguration) **CWE**: CWE-1022 (Use of Web Link to Untrusted Target with window.opener Access)

**Опис**. `target="_blank"` без `rel="noopener"` дає відкритій сторінці доступ до `window.opener` → reverse tabnabbing. У сучасних браузерах для same-origin поведінка змінилась, але для cross-origin без явного rel — атака можлива.

**AST-сигнатура**:
- `JsxOpeningElement` з `tagName === 'a'`
- атрибут `target` зі значенням `'_blank'`
- немає атрибута `rel`, або `rel` не містить `noopener`

**Remediation**. Додати `rel="noopener noreferrer"`.

---

## R-04 — `javascript:` URL у `href` / `src`

**OWASP**: A03:2021 **CWE**: CWE-79

**Опис**. `<a href="javascript:...">` або `<iframe src={user}>` де `user` починається з `javascript:` — XSS. React блокує це починаючи з 16.9 з warning, але в TS/HTML/Vue все ще проходить.

**AST-сигнатура**:
- `JsxAttribute` `href`/`src` зі значенням, що матчить `/^javascript:/i`
- АБО динамічне значення зі змінної без перевірки `startsWith('http')`/`new URL()` валідації

**Remediation**. Валідувати протокол через `new URL(value).protocol === 'https:'` або allowlist.

---

## R-05 — Prototype pollution

**OWASP**: A08:2021 (Software and Data Integrity Failures) **CWE**: CWE-1321 (Improperly Controlled Modification of Object Prototype Attributes)

**Опис**. Рекурсивний merge `Object.assign({}, untrusted)` або кастомні `deepMerge`/`extend` з ключами `__proto__`, `constructor.prototype` змінюють `Object.prototype` глобально → bypass authn, RCE у Node-частині bundle.

**AST-сигнатура**:
- `CallExpression` з callee `Object.assign` де перший аргумент — `{}` і другий — змінна з невідомим джерелом
- кастомні функції з рекурсивним обходом ключів без перевірки `key === '__proto__' | 'constructor' | 'prototype'`

**Remediation**. Використати `structuredClone`, `Object.create(null)` як target, або lodash `_.merge` з версією без CVE; перевіряти ключі.

---

## R-06 — Токени/секрети у `localStorage` / `sessionStorage`

**OWASP**: A02:2021 (Cryptographic Failures) **CWE**: CWE-922 (Insecure Storage of Sensitive Information)

**Опис**. `localStorage.setItem('token', ...)`, `'jwt'`, `'access_token'`, `'refresh_token'` — доступно будь-якому скрипту на сторінці; XSS = повна крадіжка токена. Стандарт — `httpOnly Secure SameSite` cookies.

**AST-сигнатура**:
- `CallExpression` `localStorage.setItem` / `sessionStorage.setItem` з першим аргументом — рядок, що містить `token | jwt | secret | password | credential | auth`
- АБО `localStorage[key] = value` з тими самими ключами

**Remediation**. Перенести у httpOnly cookies (потрібна координація з backend) або використати `IndexedDB` з encryption-at-rest + memory-only token holder.

---

## R-07 — Hard-coded secrets

**OWASP**: A07:2021 (Identification and Authentication Failures) **CWE**: CWE-798 (Use of Hard-coded Credentials)

**Опис**. Паттерни: `apiKey: 'sk-...'`, `Authorization: 'Bearer eyJ...'`, AWS keys (`AKIA[0-9A-Z]{16}`), Google API keys (`AIza[0-9A-Za-z-_]{35}`), Stripe (`sk_live_`, `pk_live_`).

**AST-сигнатура**:
- `StringLiteral` що матчить regexes:
  - `/AKIA[0-9A-Z]{16}/` (AWS)
  - `/AIza[0-9A-Za-z\-_]{35}/` (Google)
  - `/sk_live_[0-9a-zA-Z]{24,}/` (Stripe live)
  - `/eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+/` (JWT)
  - `/-----BEGIN (RSA |EC )?PRIVATE KEY-----/`
- `PropertyAssignment` з ключем `apiKey | api_key | secret | token | password | privateKey`, значенням — non-empty StringLiteral з ентропією > 4.0 біт/символ

**False positive guard**. Файли в `.test.ts` / `__mocks__/` з очевидними тестовими значеннями (`'test-key-123'`, `'fake-token'`) → FP.

**Remediation**. Перенести у `.env` (з `VITE_` prefix лише для **public** значень), у secret manager, або перевести у backend proxy.

---

## R-08 — Open redirect

**OWASP**: A01:2021 (Broken Access Control) **CWE**: CWE-601 (URL Redirection to Untrusted Site)

**Опис**. `window.location.href = params.get('redirect')` без allowlist → phishing.

**AST-сигнатура**:
- Присвоєння `window.location` / `window.location.href` / `location.assign` з аргументом, що походить (через taint) з `URLSearchParams`, `useSearchParams`, `props.location`, `route.query`.

**Remediation**. Allowlist домени, або relative-path-only валідація (`new URL(target, location.origin).origin === location.origin`).

---

## R-09 — `postMessage` без перевірки origin

**OWASP**: A04:2021 (Insecure Design) **CWE**: CWE-346 (Origin Validation Error)

**Опис**. `window.addEventListener('message', e => { /* без перевірки e.origin */ })` приймає повідомлення з будь-якого фрейма → XSS у host-сторінці через child frame.

**AST-сигнатура**:
- `addEventListener('message', handler)`
- handler не звертається до `e.origin` АБО порівняння `e.origin === '*'`

**Remediation**. Перевіряти `event.origin` проти allowlist; для відправлення — `targetWindow.postMessage(data, EXACT_ORIGIN)` (не `'*'`).

---

## R-10 — Відсутній CSP / SRI

**OWASP**: A05:2021 **CWE**: CWE-693 (Protection Mechanism Failure)

**Опис**. У `index.html`/`vite.config.ts`/Webpack-конфігу немає `<meta http-equiv="Content-Security-Policy">` або `Content-Security-Policy` header. Зовнішні `<script src>` без `integrity=` атрибута — supply chain ризик.

**AST/text-сигнатура**:
- `index.html` без `<meta http-equiv="Content-Security-Policy">` і без `helmet`/`vite-plugin-csp` у конфігу
- `<script src="https://...">` без `integrity` і `crossorigin`

**Remediation**. Додати CSP з `default-src 'self'`, `script-src 'self' 'nonce-...'`. Для CDN-скриптів — `integrity="sha384-..." crossorigin="anonymous"`.

---

## R-11 — CORS misconfig у клієнтських wrappers

**OWASP**: A05:2021 **CWE**: CWE-942 (Permissive Cross-domain Policy)

**Опис**. `fetch(url, {credentials: 'include', mode: 'no-cors'})` або кастомні Apollo links з `Access-Control-Allow-Origin: *` для credentialed endpoints.

**AST-сигнатура**:
- `fetch` / `axios` configs з одночасним `credentials: 'include'` і wildcard origin/`mode: 'no-cors'`.

**Remediation**. Використати exact origin; ніколи не комбінувати credentials з wildcard.

---

## R-12 — Залежності з відомими CVE

**OWASP**: A06:2021 (Vulnerable and Outdated Components) **CWE**: CWE-1395

**Опис**. Запуск `pnpm audit --json` → парсинг `advisories`. Severity мапиться напряму.

**Команда**:
```sh
pnpm audit --json --audit-level low > audit.json || true
```

**Remediation**. `pnpm update <pkg>`, або `pnpm.overrides` для transitive deps.

---

# BE Rules — Detail

## B-01 — SQL injection через raw query

**OWASP**: A03:2021 (Injection) **CWE**: CWE-89 (Improper Neutralization of Special Elements used in an SQL Command)

**Опис**. `db.query(\`SELECT * FROM users WHERE id = ${id}\`)`, `knex.raw('... ' + req.body.x)`, `pool.query`, `client.query`, `sequelize.query` — raw SQL з конкатенацією/інтерполяцією user input.

**AST-сигнатура**:
- `CallExpression` з callee, що матчить `(\.|^)(raw|query|execute)$`
- Перший аргумент — `TemplateExpression` з `${...}` (interpolation), АБО
- `BinaryExpression` з оператором `+` і operand-ами, що містять `req\.|request\.|params|query|body|input|user`.

**Remediation**. Використовувати **prepared statements** з placeholders (`?`/`$1`/`:name`) або query builders типу Knex/Sequelize ORM.

**OWASP Cheat Sheet**: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html

---

## B-02 — Command injection через `child_process`

**OWASP**: A03:2021 **CWE**: CWE-78 (OS Command Injection)

**Опис**. `exec/execSync/spawn/spawnSync/execFile/execFileSync` з template literal або concat, де input з `req`/`request`/`params`/`query`/`body`/`process.argv`. Призводить до RCE.

**AST-сигнатура**:
- `CallExpression` з callee `(^|\.)(exec|execSync|spawn|spawnSync|execFile|execFileSync)$`
- Перший аргумент не літерал АБО містить tainted-токени, АБО — template/binary expression.

**Remediation**. `execFile(cmd, [args])` (без shell), валідовані whitelist значень, або повна відмова від shell-out у користь спеціалізованих библіотек.

---

## B-03 — NoSQL injection

**OWASP**: A03:2021 **CWE**: CWE-943 (Improper Neutralization of Special Elements in Data Query Logic)

**Опис**. `User.find(req.body)` дозволяє атакеру передати `{$gt:""}`, `{$ne:null}` як filter — вибирає всі записи. `$where: req.query.fn` — JS-injection.

**AST-сигнатура**:
- `PropertyAssignment` з ключем `$where` і non-literal value.
- `CallExpression` з callee `\.(find|findOne|findOneAndUpdate|updateOne|updateMany|deleteOne|deleteMany)$` і першим аргументом, який починається з `req.body|req.query|request.body|request.query`.

**Remediation**. Явно витягати конкретні поля: `User.find({ name: String(req.body.name) })`. Валідація схемою (Joi, zod). Заборонити `$where` query operator.

---

## B-04 — Server-side request forgery (SSRF)

**OWASP**: A10:2021 (SSRF) **CWE**: CWE-918

**Опис**. Сервер виконує HTTP-запит на адресу, контрольовану користувачем. Дозволяє атакеру дістати internal services (metadata, localhost), сканувати мережу.

**AST-сигнатура**:
- `CallExpression` з callee `^(fetch|axios|axios\.(get|post|put|delete|patch|request)|http\.get|https\.get|got|request|node-fetch)$`.
- Аргумент містить `req.body|req.query|req.params|request.body|request.query|request.params`.

**Remediation**. Allowlist дозволених host-ів. Заборонити приватні IP (`10.0.0.0/8`, `192.168.0.0/16`, `127.0.0.0/8`, `169.254.169.254`). Окремий outbound proxy.

---

## B-05 — Path traversal у `fs.*`

**OWASP**: A01:2021 (Broken Access Control) **CWE**: CWE-22

**Опис**. `fs.readFile(req.query.name)` дозволяє `../../etc/passwd`. Розкриває файлову систему сервера.

**AST-сигнатура**:
- `CallExpression` з callee `^(fs|fs\/promises|fsp)\.(readFile|readFileSync|createReadStream|writeFile|writeFileSync|createWriteStream|unlink|unlinkSync|stat|statSync|access|accessSync)$`.
- Аргумент містить `req.body|req.query|req.params|request.body|request.query|request.params`.
- І НЕ містить `path.resolve` або `path.normalize`.

**Remediation**. `path.resolve(BASE, sanitized)` + перевірка, що результат починається з `BASE`. Або заборонити `..` у шляху.

---

## B-06 — Unsafe deserialization / dynamic code execution

**OWASP**: A08:2021 (Software and Data Integrity Failures) **CWE**: CWE-502

**Опис**. `eval(req.body.code)`, `vm.runInThisContext`, `node-serialize.unserialize` — RCE. `node-serialize` має відому RCE через `__js_function`.

**AST-сигнатура**:
- `eval(non-literal)`.
- `CallExpression` callee `^vm\.(runInThisContext|runInContext|runInNewContext|compileFunction)$`.
- `serialize/unserialize`, `node-serialize.unserialize`.
- `Function(...)` або `new Function(...)`.

**Remediation**. Замість `eval` — `JSON.parse` для даних, query builders для DSL. `vm` тільки з sandbox-ed контекстом. Замінити `node-serialize` на `JSON.parse`.

---

## B-07 — Weak crypto

**OWASP**: A02:2021 (Cryptographic Failures) **CWE**: CWE-327 (Use of a Broken or Risky Cryptographic Algorithm)

**Опис**. `crypto.createHash('md5')` для паролів — broken (rainbow tables). `jwt.sign(..., 'literalSecret', ...)` — secret у git history → token forgery.

**AST-сигнатура**:
- `crypto.createHash('md5'|'sha1')`.
- `jwt.sign(..., LITERAL_SECRET, ...)` / `jwt.verify(..., LITERAL_SECRET, ...)` де secret — non-empty literal без test/fake/dummy markers.

**Remediation**. Паролі: `bcrypt`, `argon2`, `scrypt` (libsodium). JWT secret: `process.env.JWT_SECRET` (>=256 біт випадковості). Для signature key — KMS.

---

## B-08 — Missing CSRF protection

**OWASP**: A01:2021 **CWE**: CWE-352 (Cross-Site Request Forgery)

**Опис**. Express `app.post('/transfer', handler)` без CSRF-token-валідації — атакер може зробити запит з імені залогіненого юзера.

**AST-сигнатура**:
- `CallExpression` з callee `^(app|router)\.(post|put|delete|patch)$`.
- Текст всього виклику не містить `csrf|csurf|csrfProtection|verifyCsrf|doubleCsrf`.
- **Severity**: low confidence (можливо global middleware) → `verdict: NEEDS_HUMAN`.

**Remediation**. `csurf` middleware або double-submit cookie pattern. SameSite=Strict cookie + Origin header check.

---

## B-09 — Missing Helmet middleware

**OWASP**: A05:2021 **CWE**: CWE-693

**Опис**. Express застосунок без `helmet()` middleware не виставляє security headers (X-Frame-Options, X-Content-Type-Options, Strict-Transport-Security тощо).

**AST/text-сигнатура**:
- Файл містить `express()` АБО `require('express')()`.
- Файл має route definitions: `app.get/post/...`, `router.X`.
- Файл НЕ містить токен `helmet`.

**Remediation**. `import helmet from 'helmet'; app.use(helmet());`.

---

## B-10 — Server hardcoded credentials у connection string

**OWASP**: A07:2021 **CWE**: CWE-798

**Опис**. `'postgres://user:password@host'` — пароль у git, у логах, у crash reports.

**AST/text-сигнатура**:
- `StringLiteral` що матчить `/^(postgres|postgresql|mongodb|mongodb\+srv|mysql|mariadb|redis|amqp|amqps):\/\/[^:@\/\s]+:[^@\s]{4,}@/`.

**Remediation**. `process.env.DATABASE_URL` або secret manager (AWS Secrets Manager, Vault, Doppler).

## B-11 — IDOR (Insecure Direct Object Reference)

**OWASP**: A01:2021 (Broken Access Control) **CWE**: CWE-639 (Authorization Bypass Through User-Controlled Key)

**Опис**. `Order.findById(req.params.id)` без перевірки `req.user.id` дозволяє будь-якому юзеру відкрити чужий об'єкт. Класична broken-access-control проблема.

**AST-сигнатура**:
- `CallExpression` з `callee.name ∈ {findById, findByPk, findOne, findUnique, getById}`
- argument містить `req.params|body|query` або `_id: req.*`
- enclosing function body не містить `req.user|currentUser|isAdmin|hasRole|where: {...userId}` evidence.

**Remediation**. `Order.findOne({ where: { id: req.params.id, userId: req.user.id } })` або explicit ownership check + 403 response. Cheat sheet: [OWASP Authorization](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html).

## B-12 — XXE (XML External Entity)

**OWASP**: A05:2021 (Security Misconfiguration) **CWE**: CWE-611

**Опис**. `libxmljs.parseXml(userXml)` за замовчуванням розгортає external entities → читання файлів сервера (`/etc/passwd`), SSRF через `<!ENTITY foo SYSTEM "http://internal/...">`.

**AST-сигнатура**:
- `libxmljs(2)?.parseXml | parseXmlString | parseHtml(...)` без options `{noent:false, nonet:true, noblanks:true}`.
- `xml2js.parseString(...)` без явних options (`explicitArray`, `explicitRoot`).

**Remediation**. `libxmljs.parseXml(xml, { noent: false, nonet: true, noblanks: true })`. Краще — JSON замість XML де можна. Cheat sheet: [OWASP XXE Prevention](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html).

## B-13 — Mass assignment

**OWASP**: A08:2021 (Software and Data Integrity Failures) **CWE**: CWE-915 (Improperly Controlled Modification of Dynamically-Determined Object Attributes)

**Опис**. `User.update(req.body)` дозволяє атакувальнику передати `{role: 'admin'}` або `{isVerified: true}` і підвищити привілеї. Те саме з `Object.assign(user, req.body)` чи `new Model({...req.body})`.

**AST-сигнатура**:
- `Object.assign(target, req.body)` де `target` НЕ `{}` (порожній — це prototype pollution = R-05).
- `Model.update|create|save|insert|insertMany|upsert(req.body, ...)`.
- `new Model({...req.body})` (spread у new).

**Remediation**. Whitelist полів: `User.update({ name: req.body.name, email: req.body.email }, ...)`. Або DTO + валідатор (zod, class-validator).

## B-14 — Server-side open redirect

**OWASP**: A01:2021 (Broken Access Control — open redirect — A01 у 2021 відсутній окремо, мапиться на CWE-601) **CWE**: CWE-601

**Опис**. `res.redirect(req.query.next)` дозволяє фішинг: `https://yourapp/login?next=https://evil.com` → юзер логіниться, його редіректить на evil.com (з referer токенами).

**AST-сигнатура**:
- `res|response.redirect(...userInput)` (включно з 2-arg формою `res.redirect(302, target)`).
- `res|response.location(userInput)`.

**Remediation**. Whitelist дозволених URL prefixes; relative URL-only (`/dashboard`); HMAC-signed token вкладений у URL. Cheat sheet: [OWASP Unvalidated Redirects](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html).

## B-15 — Server-side template injection (SSTI)

**OWASP**: A03:2021 (Injection) **CWE**: CWE-94 (Improper Control of Generation of Code)

**Опис**. `res.render(req.body.template)` або `pug.compile(userTemplate)` — атакувальник передає шаблон з `{{constructor.constructor('return process')()}}` → RCE на сервері. SSTI = найкритичніша injection-вразливість після SQLi.

**AST-сигнатура**:
- `res|response.render(req.X, ...)` — template name/шлях з користувача.
- `pug|handlebars|ejs|mustache|nunjucks|dot|liquidjs|hogan|swig|eta.compile|render|renderFile|renderString(req.X, ...)`.

**Remediation**. Render тільки з whitelist шаблонів: `res.render('home', data)`. Ніколи не приймати template body з юзера. Cheat sheet: [PortSwigger SSTI](https://portswigger.net/web-security/server-side-template-injection).

---

# Docker / Container Rules — Detail

## D-01 — Container runs as root

**OWASP**: A05:2021 (Security Misconfiguration) **CWE**: CWE-250 (Execution with Unnecessary Privileges)

**Опис**. Без `USER` directive контейнер виконується від root. RCE у застосунку → root всередині контейнера → атаки на host (через kernel exploits, mounted volumes, network).

**Сигнатура**: Dockerfile не містить `USER` directive, або останній `USER` — `root` чи `0`.

**Remediation**. `RUN groupadd -r app && useradd -r -g app app && USER app`. Або use `USER node` у Node.js images.

**CIS Benchmark**: 4.1 (Create a user for the container).

---

## D-02 — Mutable `latest` tag у `FROM`

**OWASP**: A06:2021 (Vulnerable and Outdated Components) **CWE**: CWE-1104

**Опис**. `FROM node:latest` — тег рухомий: за час між builds на той же тег може потрапити інша версія з різною safety-баговістю. Невідтворювані builds, supply-chain ризик.

**Сигнатура**: `FROM image:latest` АБО `FROM image` без тегу для канонічних public images (node/python/ubuntu/...). Allow-list: digest pinning `image@sha256:...`.

**Remediation**. Pin до конкретного тегу: `FROM node:20.11.1-alpine3.19`. Краще — digest: `FROM node:20.11.1-alpine3.19@sha256:abc...`.

---

## D-03 — Hardcoded secret у Dockerfile ENV/ARG

**OWASP**: A07:2021 (Identification and Authentication Failures) **CWE**: CWE-798

**Опис**. `ENV API_KEY=AKIA...` — секрет у image layer, доступний `docker history`, у registry, у логах CI.

**Сигнатура**: `ENV` або `ARG` де ключ матчить `(API[_-]?KEY|SECRET|TOKEN|PASSWORD|PRIVATE[_-]?KEY|ACCESS[_-]?KEY|AUTH|JWT|CREDENTIAL)` і значення:
- матчить known patterns (AWS AKIA, Google AIza, Stripe sk_live_, GitHub ghp_, JWT eyJ...) АБО
- має ентропію ≥4 і довжину ≥20.

**Remediation**. BuildKit secrets: `RUN --mount=type=secret,id=mykey ...`. Або runtime: `docker run -e API_KEY=$API_KEY`.

---

## D-04 — `ADD` для local files

**OWASP**: A05:2021 **CWE**: CWE-829

**Опис**. `ADD` має побічні ефекти — auto-extract tarballs, fetch remote URLs з MITM-ризиками. `COPY` — простіший і передбачуваний.

**Сигнатура**: `ADD` де source не URL і не tarball.

**Remediation**. Замінити на `COPY`. `ADD` — тільки для tarball auto-extract або URL fetch (з SHA-checksum).

**Docker docs**: https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#add-or-copy

---

## D-05 — `privileged: true` у docker-compose

**OWASP**: A04:2021 (Insecure Design) **CWE**: CWE-250

**Опис**. `privileged: true` дає контейнеру всі capabilities, доступ до всіх devices, відключає cgroup-обмеження. Container ≈ root на host.

**Сигнатура**: YAML рядок `^\s*privileged\s*:\s*true\s*$`.

**Remediation**. Замість privileged — конкретні `cap_add: [SYS_TIME]`. Якщо потрібен access до GPU — `--gpus all` (Docker) або `runtimeClassName: nvidia` (k8s).

---

## D-06 — `network_mode: host`

**OWASP**: A04:2021 **CWE**: CWE-668 (Exposure of Resource to Wrong Sphere)

**Опис**. Container використовує network stack хоста — обходить Docker network isolation. Атакер у контейнері може sniff/spoof host traffic.

**Сигнатура**: YAML рядок `^\s*network_mode\s*:\s*['"]?host['"]?\s*$`.

**Remediation**. Default bridge network або custom network. Якщо потрібен зовнішній порт — `ports: [3000:3000]`.

---

## D-07 — Mount of `/var/run/docker.sock`

**OWASP**: A05:2021 **CWE**: CWE-732 (Incorrect Permission Assignment)

**Опис**. Mount Docker socket дозволяє container керувати Docker daemon хоста — створювати привілейовані контейнери, mount root filesystem хоста, exfiltrate secrets з інших контейнерів. **Повний container escape**.

**Сигнатура**: YAML рядок містить `/var/run/docker.sock`.

**Remediation**. Не монтувати docker.sock. Якщо потрібен Docker-in-Docker — використати `dind` rootless або socket proxy (Tecnativa/docker-socket-proxy) з обмеженими endpoints.

---

## D-08 — `apt-get install` без safety flags

**OWASP**: A06:2021 **CWE**: CWE-1104

**Опис**. `apt-get install -y curl` без `--no-install-recommends` — bloats image (більше attack surface). Без `pkg=version` — не відтворюваний build, можна непомітно оновитись на vulnerable version.

**Сигнатура**: `RUN` рядок містить `apt-get install` (або `apt install`) без `--no-install-recommends` І без `pkg=version` patterns.

**Remediation**. `RUN apt-get update && apt-get install -y --no-install-recommends curl=7.81.0-1ubuntu1.16 && rm -rf /var/lib/apt/lists/*`.
