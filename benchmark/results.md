# Benchmark results

_Generated: 2026-06-07T22:26:19.857Z_

- Corpora: 7
- Total cases: 87
- Seeds per case: 3
- Provider: openai
- Model: gpt-5

## Corpus: `benchmark/expected`

| Case | Expected | Detected (best run) | Verdict | Latency (median) | Cost (median) |
|------|----------|----------------------|---------|------------------|----------------|
| 01_dom_xss_introduction | R-02 | R-02 | TP×1 | 26380ms | $0.0269 |
| 02_ssrf_allowlist_removed | B-04 | B-04 | TP×1 | 17729ms | $0.0199 |
| 03_safe_refactor | — (TN expected) | — | TN | 8399ms | $0.0092 |
| 04_idor_ambiguous | B-11 | — | FN×1 | 23253ms | $0.0219 |
| 05_sanitizer_removed | R-01 | R-01 | TP×1 | 30694ms | $0.0230 |
| 06_dockerfile_root_user | D-01 | D-01 | TP×1 | 27776ms | $0.0215 |
| 07_renamed_with_change | B-01 | B-01 | TP×1 | 23829ms | $0.0298 |
| 08_deleted_file | — (TN expected) | — | TN | 13300ms | $0.0123 |
| 09_binary_file | — (TN expected) | — | TN | 8256ms | $0.0103 |
| 10_error_exposure | B-16 | B-16 | TP×1 | 19056ms | $0.0209 |
| 11_silent_swallow | B-17 | B-17 | TP×1 | 23333ms | $0.0253 |

| Mode | TP | FP | FN | TN | Precision (95% CI) | Recall (95% CI) | F1 (95% CI) |
|------|----|----|----|----|---------------------|------------------|--------------|
| Strict (rule_id exact) | 7 | 0 | 1 | 3 | 1 [0.646, 1] | 0.875 [0.529, 0.978] | **0.933 [0.769, 1]** |
| Loose (OWASP+CWE match) | 7 | 0 | 1 | 3 | 1 [0.646, 1] | 0.875 [0.529, 0.978] | **0.933 [0.769, 1]** |

<sub>Precision / recall CI: Wilson score interval (Brown–Cai–DasGupta 2001). F1 CI: non-parametric bootstrap over cases (B=1000, seed=42, percentile method). Both at 95% confidence.</sub>

## Corpus: `benchmark/independent_corpus`

| Case | Expected | Detected (best run) | Verdict | Latency (median) | Cost (median) |
|------|----------|----------------------|---------|------------------|----------------|
| i01_prototype_pollution_argv_merge | R-05 | R-05 | TP×1 | 45119ms | $0.0400 |
| i02_xxe_xml_parser | B-12 | B-12 | TP×1 | 27044ms | $0.0261 |
| i03_command_injection_image_convert | B-02 | B-02 | TP×1 | 27032ms | $0.0262 |
| i04_path_traversal_template_loader | B-05 | B-05 | TP×1 | 26447ms | $0.0323 |
| i05_server_side_open_redirect | B-14 | B-14 | TP×1 | 20832ms | $0.0191 |
| i06_mass_assignment_user_update | B-13 | B-13 | TP×1 | 16190ms | $0.0210 |
| i07_weak_crypto_password_hash | B-07 | B-07, B-07 | TP×1 | 30463ms | $0.0462 |
| i08_csrf_protection_removed | B-08 | B-08 | TP×1 | 31324ms | $0.0311 |
| i09_nosql_injection_mongoose_where | B-03 | B-03 | TP×1 | 22682ms | $0.0205 |
| i10_safe_helmet_added | — (TN expected) | — | TN | 25423ms | $0.0196 |

| Mode | TP | FP | FN | TN | Precision (95% CI) | Recall (95% CI) | F1 (95% CI) |
|------|----|----|----|----|---------------------|------------------|--------------|
| Strict (rule_id exact) | 9 | 1 | 0 | 1 | 0.9 [0.596, 0.982] | 1 [0.701, 1] | **0.947 [0.842, 1]** |
| Loose (OWASP+CWE match) | 9 | 1 | 0 | 1 | 0.9 [0.596, 0.982] | 1 [0.701, 1] | **0.947 [0.842, 1]** |

<sub>Precision / recall CI: Wilson score interval (Brown–Cai–DasGupta 2001). F1 CI: non-parametric bootstrap over cases (B=1000, seed=42, percentile method). Both at 95% confidence.</sub>

## Corpus: `benchmark/complex_corpus`

| Case | Expected | Detected (best run) | Verdict | Latency (median) | Cost (median) |
|------|----------|----------------------|---------|------------------|----------------|
| c01_ssrf_via_extracted_helper | B-04 | — | FN×1 | 30980ms | $0.0302 |
| c02_compositional_xss_regression | R-01 | R-01 | TP×1 | 54457ms | $0.0495 |
| c03_authz_check_moved_breaks_semantics | B-11 | B-11 | TP×1 | 44301ms | $0.0462 |
| c04_secret_buried_in_refactor | R-07 | R-07 | TP×1 | 60506ms | $0.0592 |
| c05_cross_file_sql_injection | B-01 | B-01 | TP×1 | 28880ms | $0.0300 |
| c06_safe_large_refactor | — (TN expected) | — | TN | 23083ms | $0.0200 |
| c07_prototype_pollution_via_merge_util | R-05 | R-05 | TP×1 | 63272ms | $0.0466 |

| Mode | TP | FP | FN | TN | Precision (95% CI) | Recall (95% CI) | F1 (95% CI) |
|------|----|----|----|----|---------------------|------------------|--------------|
| Strict (rule_id exact) | 5 | 0 | 1 | 1 | 1 [0.566, 1] | 0.833 [0.436, 0.97] | **0.909 [0.667, 1]** |
| Loose (OWASP+CWE match) | 5 | 0 | 1 | 1 | 1 [0.566, 1] | 0.833 [0.436, 0.97] | **0.909 [0.667, 1]** |

<sub>Precision / recall CI: Wilson score interval (Brown–Cai–DasGupta 2001). F1 CI: non-parametric bootstrap over cases (B=1000, seed=42, percentile method). Both at 95% confidence.</sub>

## Corpus: `benchmark/nodegoat_corpus`

| Case | Expected | Detected (best run) | Verdict | Latency (median) | Cost (median) |
|------|----------|----------------------|---------|------------------|----------------|
| ng01_nosql_injection_allocations | B-03 | B-03 | TP×1 | 31660ms | $0.0342 |
| ng02_eval_injection_contributions | B-06 | B-06, B-06, B-06 | TP×1 | 34027ms | $0.0260 |
| ng03_ssrf_research | B-04 | B-04 | TP×1 | 27699ms | $0.0270 |
| ng04_idor_allocations | B-11 | — | FN×1 | 28346ms | $0.0293 |
| ng05_missing_csrf | B-08 | B-08 | TP×1 | 37771ms | $0.0292 |
| ng06_open_redirect_learn | B-14 | B-14 | TP×1 | 19427ms | $0.0200 |
| ng07_xss_js_href_profile | R-04 | R-04 | TP×1 | 29567ms | $0.0305 |
| ng08_missing_helmet | B-09 | B-09 | TP×1 | 39794ms | $0.0429 |
| ng09_mass_assignment_memos | B-13 | B-13 | TP×1 | 24045ms | $0.0240 |
| ng10_redos_profile | B-18 | B-18 | TP×1 | 26710ms | $0.0372 |
| ng11_missing_func_authz_benefits | B-19 | B-19, B-19 | TP×1 | 23980ms | $0.0283 |
| ng12_insecure_cookie_flags | B-20 | B-20 | TP×1 | 38347ms | $0.0403 |
| ng13_plaintext_password | B-21 | B-21, B-21 | TP×1 | 35940ms | $0.0431 |

| Mode | TP | FP | FN | TN | Precision (95% CI) | Recall (95% CI) | F1 (95% CI) |
|------|----|----|----|----|---------------------|------------------|--------------|
| Strict (rule_id exact) | 12 | 4 | 1 | 0 | 0.75 [0.505, 0.898] | 0.923 [0.667, 0.986] | **0.828 [0.688, 0.963]** |
| Loose (OWASP+CWE match) | 12 | 4 | 1 | 0 | 0.75 [0.505, 0.898] | 0.923 [0.667, 0.986] | **0.828 [0.688, 0.963]** |

<sub>Precision / recall CI: Wilson score interval (Brown–Cai–DasGupta 2001). F1 CI: non-parametric bootstrap over cases (B=1000, seed=42, percentile method). Both at 95% confidence.</sub>

## Corpus: `benchmark/juiceshop_corpus`

| Case | Expected | Detected (best run) | Verdict | Latency (median) | Cost (median) |
|------|----------|----------------------|---------|------------------|----------------|
| js01_sqli_login | B-01 | B-01 | TP×1 | 29261ms | $0.0293 |
| js02_nosqli_trackorder | B-03 | B-03 | TP×1 | 30421ms | $0.0319 |
| js03_weak_crypto_md5 | B-07 | B-07 | TP×1 | 26741ms | $0.0280 |
| js04_ssrf_profileimage | B-04 | B-04 | TP×1 | 33876ms | $0.0339 |
| js05_xxe_fileupload | B-12 | B-12 | TP×1 | 25349ms | $0.0322 |
| js06_zipslip_fileupload | B-05 | B-05 | TP×1 | 42532ms | $0.0401 |
| js07_rce_b2border | B-06 | B-06 | TP×1 | 46582ms | $0.0565 |
| js08_idor_basket | B-11 | B-11 | TP×1 | 24695ms | $0.0212 |
| js09_open_redirect | B-14 | B-14 | TP×1 | 27490ms | $0.0278 |
| js10_ssti_userprofile | B-15 | — | FN×1 | 29863ms | $0.0298 |
| js11_jwt_no_alg | B-22 | B-22 | TP×1 | 32647ms | $0.0286 |
| tn01_parameterised_login | — (TN expected) | — | TN | 15444ms | $0.0175 |
| tn02_hardened_redirect | — (TN expected) | B-14 | FP×1 | 40402ms | $0.0381 |

| Mode | TP | FP | FN | TN | Precision (95% CI) | Recall (95% CI) | F1 (95% CI) |
|------|----|----|----|----|---------------------|------------------|--------------|
| Strict (rule_id exact) | 10 | 1 | 1 | 1 | 0.909 [0.623, 0.984] | 0.909 [0.623, 0.984] | **0.909 [0.75, 1]** |
| Loose (OWASP+CWE match) | 10 | 1 | 1 | 1 | 0.909 [0.623, 0.984] | 0.909 [0.623, 0.984] | **0.909 [0.75, 1]** |

<sub>Precision / recall CI: Wilson score interval (Brown–Cai–DasGupta 2001). F1 CI: non-parametric bootstrap over cases (B=1000, seed=42, percentile method). Both at 95% confidence.</sub>

## Corpus: `benchmark/snyk_corpus`

| Case | Expected | Detected (best run) | Verdict | Latency (median) | Cost (median) |
|------|----------|----------------------|---------|------------------|----------------|
| sn01 | R-03 | R-03 | TP×1 | 25156ms | $0.0267 |
| sn02 | R-06 | R-06 | TP×1 | 30010ms | $0.0366 |
| sn03 | R-08 | R-08 | TP×1 | 22530ms | $0.0257 |
| sn04 | R-09 | R-09 | TP×1 | 35717ms | $0.0367 |
| sn05 | R-10 | R-10 | TP×1 | 32020ms | $0.0364 |
| sn06 | R-11 | R-11 | TP×1 | 35198ms | $0.0311 |
| sn07 | B-10 | B-10 | TP×1 | 25290ms | $0.0238 |

| Mode | TP | FP | FN | TN | Precision (95% CI) | Recall (95% CI) | F1 (95% CI) |
|------|----|----|----|----|---------------------|------------------|--------------|
| Strict (rule_id exact) | 7 | 0 | 0 | 0 | 1 [0.646, 1] | 1 [0.646, 1] | **1 [1, 1]** |
| Loose (OWASP+CWE match) | 7 | 0 | 0 | 0 | 1 [0.646, 1] | 1 [0.646, 1] | **1 [1, 1]** |

<sub>Precision / recall CI: Wilson score interval (Brown–Cai–DasGupta 2001). F1 CI: non-parametric bootstrap over cases (B=1000, seed=42, percentile method). Both at 95% confidence.</sub>

## Corpus: `benchmark/oss_pilot`

| Case | Expected | Detected (best run) | Verdict | Latency (median) | Cost (median) |
|------|----------|----------------------|---------|------------------|----------------|
| Automattic__mongoose__pr16278 | — (TN expected) | — | TN | 12703ms | $0.0154 |
| Automattic__mongoose__pr16279 | — (TN expected) | — | TN | 13496ms | $0.0106 |
| axios__axios__pr10889 | — (TN expected) | — | TN | 11520ms | $0.0146 |
| axios__axios__pr10890 | — (TN expected) | — | TN | 10831ms | $0.0155 |
| expressjs__express__pr7181 | — (TN expected) | — | TN | 35792ms | $0.0225 |
| expressjs__express__pr7224 | — (TN expected) | — | TN | 20955ms | $0.0251 |
| expressjs__multer__pr1373 | — (TN expected) | — | TN | 18508ms | $0.0184 |
| fastify__fastify__pr6458 | — (TN expected) | — | TN | 15844ms | $0.0175 |
| fastify__fastify__pr6714 | — (TN expected) | — | TN | 14845ms | $0.0175 |
| form-data__form-data__pr4 | — (TN expected) | NEW_PATTERN | FP×1 | 40468ms | $0.0522 |
| form-data__form-data__pr582 | — (TN expected) | — | TN | 18545ms | $0.0174 |
| koajs__koa__pr1927 | — (TN expected) | — | TN | 10200ms | $0.0150 |
| koajs__koa__pr1930 | — (TN expected) | NEW_PATTERN | FP×1 | 45778ms | $0.0452 |
| koajs__koa__pr1946 | — (TN expected) | — | TN | 17600ms | $0.0158 |
| nodemailer__nodemailer__pr1814 | — (TN expected) | — | TN | 24732ms | $0.0281 |
| nodemailer__nodemailer__pr1815 | — (TN expected) | — | TN | 10922ms | $0.0102 |
| nodemailer__nodemailer__pr1816 | — (TN expected) | — | TN | 18670ms | $0.0199 |
| op01_follow-redirects_CVE-2023-26159 | B-14 | — | FN×1 | 21667ms | $0.0188 |
| op02_node-semver_CVE-2022-25883 | B-18 | B-18 | TP×1 | 36260ms | $0.0397 |
| op03_lodash_CVE-2020-8203 | R-05 | R-05 | TP×1 | 37763ms | $0.0389 |
| op04_lodash_CVE-2021-23337 | B-15 | B-15 | TP×1 | 40827ms | $0.0382 |
| op05_minimist_CVE-2020-7598 | R-05 | R-05 | TP×1 | 50869ms | $0.0459 |
| op06_ansi-regex_CVE-2021-3807 | B-18 | — | FN×1 | 28091ms | $0.0379 |
| op07_json5_CVE-2022-46175 | R-05 | R-05 | TP×1 | 65578ms | $0.0432 |
| validatorjs__validator.js__pr2695 | — (TN expected) | — | TN | 12602ms | $0.0122 |
| validatorjs__validator.js__pr2701 | — (TN expected) | — | TN | 14725ms | $0.0123 |

| Mode | TP | FP | FN | TN | Precision (95% CI) | Recall (95% CI) | F1 (95% CI) |
|------|----|----|----|----|---------------------|------------------|--------------|
| Strict (rule_id exact) | 5 | 2 | 2 | 17 | 0.714 [0.359, 0.918] | 0.714 [0.359, 0.918] | **0.714 [0.333, 0.933]** |
| Loose (OWASP+CWE match) | 5 | 2 | 2 | 17 | 0.714 [0.359, 0.918] | 0.714 [0.359, 0.918] | **0.714 [0.333, 0.933]** |

<sub>Precision / recall CI: Wilson score interval (Brown–Cai–DasGupta 2001). F1 CI: non-parametric bootstrap over cases (B=1000, seed=42, percentile method). Both at 95% confidence.</sub>

## Generalisation gaps

Each row is `(F1 of corpus A) − (F1 of corpus B)`. The expected (healthy) trend is monotonically degrading F1 from smoke → independent → complex → oss_pilot, reflecting cases drifting further from the catalog's design assumptions.

A large positive gap (>0.20) on any step signals over-fit at that level; a flat or inverted gap suggests the next corpus is too easy.

| Transition | Strict F1 (a → b) | Strict gap | Loose F1 (a → b) | Loose gap |
|------------|--------------------|-----------|-------------------|-----------|
| smoke → independent | `0.933` → `0.947` | **-0.014** | `0.933` → `0.947` | **-0.014** |
| independent → complex | `0.947` → `0.909` | **+0.038** | `0.947` → `0.909` | **+0.038** |
| complex → nodegoat | `0.909` → `0.828` | **+0.081** | `0.909` → `0.828` | **+0.081** |
| nodegoat → juiceshop | `0.828` → `0.909` | **-0.081** | `0.828` → `0.909` | **-0.081** |
| juiceshop → oss_pilot | `0.909` → `0.714` | **+0.195** | `0.909` → `0.714` | **+0.195** |

