# Benchmark results

_Generated: 2026-05-14T10:20:22.437Z_

- Corpora: 3
- Total cases: 26
- Seeds per case: 1
- Provider: openai
- Model: cheap

> ⚠️  The `benchmark/expected/` corpus is **curated by the same author who wrote the catalog** and serves only as a smoke / regression set.
> The `benchmark/independent_corpus/` corpus reproduces patterns from publicly disclosed CVE families and was not used to design the catalog.
> Report both numbers separately — the gap between them is the honest indicator of generalisability.

## Corpus: `benchmark/expected`

| Case | Expected | Detected (best run) | Verdict | Latency (median) | Cost (median) |
|------|----------|----------------------|---------|------------------|----------------|
| 01_dom_xss_introduction | R-02 | R-02 | TP×1 | 10621ms | $0.0040 |
| 02_ssrf_allowlist_removed | B-04 | B-04 | TP×1 | 6932ms | $0.0022 |
| 03_safe_refactor | — (TN expected) | — | TN | 3572ms | $0.0019 |
| 04_idor_ambiguous | B-11 | — | FN×1 | 9340ms | $0.0022 |
| 05_sanitizer_removed | R-01 | R-01 | TP×1 | 7112ms | $0.0022 |
| 06_dockerfile_root_user | D-01 | D-01 | TP×1 | 6048ms | $0.0021 |
| 07_renamed_with_change | B-01 | B-01 | TP×1 | 8453ms | $0.0021 |
| 08_deleted_file | — (TN expected) | — | TN | 4163ms | $0.0020 |
| 09_binary_file | — (TN expected) | — | TN | 2580ms | $0.0019 |

| Mode | TP | FP | FN | TN | Precision | Recall | F1 |
|------|----|----|----|----|-----------|--------|----|
| Strict (rule_id exact) | 5 | 0 | 1 | 3 | 1 | 0.833 | **0.909** |
| Loose (OWASP+CWE match) | 5 | 0 | 1 | 3 | 1 | 0.833 | **0.909** |

## Corpus: `benchmark/independent_corpus`

| Case | Expected | Detected (best run) | Verdict | Latency (median) | Cost (median) |
|------|----------|----------------------|---------|------------------|----------------|
| i01_prototype_pollution_argv_merge | R-05 | R-05 | TP×1 | 7128ms | $0.0022 |
| i02_xxe_xml_parser | B-12 | B-12 | TP×1 | 7752ms | $0.0021 |
| i03_command_injection_image_convert | B-02 | B-02 | TP×1 | 7731ms | $0.0021 |
| i04_path_traversal_template_loader | B-05 | B-05 | TP×1 | 7878ms | $0.0021 |
| i05_server_side_open_redirect | B-14 | B-14 | TP×1 | 6293ms | $0.0021 |
| i06_mass_assignment_user_update | B-13 | B-13 | TP×1 | 7337ms | $0.0022 |
| i07_weak_crypto_password_hash | B-07 | B-07 | TP×1 | 6947ms | $0.0021 |
| i08_csrf_protection_removed | B-08 | B-08 | TP×1 | 8299ms | $0.0021 |
| i09_nosql_injection_mongoose_where | B-03 | B-03 | TP×1 | 6822ms | $0.0022 |
| i10_safe_helmet_added | — (TN expected) | — | TN | 3557ms | $0.0020 |

| Mode | TP | FP | FN | TN | Precision | Recall | F1 |
|------|----|----|----|----|-----------|--------|----|
| Strict (rule_id exact) | 9 | 0 | 0 | 1 | 1 | 1 | **1** |
| Loose (OWASP+CWE match) | 9 | 0 | 0 | 1 | 1 | 1 | **1** |

## Corpus: `benchmark/complex_corpus`

| Case | Expected | Detected (best run) | Verdict | Latency (median) | Cost (median) |
|------|----------|----------------------|---------|------------------|----------------|
| c01_ssrf_via_extracted_helper | B-04 | B-04 | TP×1 | 6082ms | $0.0022 |
| c02_compositional_xss_regression | R-01 | — | FN×1 | 7039ms | $0.0022 |
| c03_authz_check_moved_breaks_semantics | B-11 | — | FN×1 | 6607ms | $0.0022 |
| c04_secret_buried_in_refactor | R-07 | B-07, B-07 | TP×1 | 8662ms | $0.0024 |
| c05_cross_file_sql_injection | B-01 | B-01 | TP×1 | 5821ms | $0.0022 |
| c06_safe_large_refactor | — (TN expected) | — | TN | 3097ms | $0.0021 |
| c07_prototype_pollution_via_merge_util | R-05 | R-05 | TP×1 | 6780ms | $0.0022 |

| Mode | TP | FP | FN | TN | Precision | Recall | F1 |
|------|----|----|----|----|-----------|--------|----|
| Strict (rule_id exact) | 4 | 1 | 2 | 1 | 0.8 | 0.667 | **0.727** |
| Loose (OWASP+CWE match) | 4 | 1 | 2 | 1 | 0.8 | 0.667 | **0.727** |

## Generalisation gaps

Each row is `(F1 of corpus A) − (F1 of corpus B)`. The expected (healthy) trend is monotonically degrading F1 from smoke → independent → complex → oss_pilot, reflecting cases drifting further from the catalog's design assumptions.

A large positive gap (>0.20) on any step signals over-fit at that level; a flat or inverted gap suggests the next corpus is too easy.

| Transition | Strict F1 (a → b) | Strict gap | Loose F1 (a → b) | Loose gap |
|------------|--------------------|-----------|-------------------|-----------|
| smoke → independent | `0.909` → `1` | **-0.091** | `0.909` → `1` | **-0.091** |
| independent → complex | `1` → `0.727` | **+0.273** | `1` → `0.727` | **+0.273** |

