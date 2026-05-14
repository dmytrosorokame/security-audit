# Benchmark results

_Generated: 2026-05-14T09:56:46.631Z_

- Corpora: 3
- Total cases: 26
- Seeds per case: 3
- Provider: openai
- Model: cheap

> ⚠️  The `benchmark/expected/` corpus is **curated by the same author who wrote the catalog** and serves only as a smoke / regression set.
> The `benchmark/independent_corpus/` corpus reproduces patterns from publicly disclosed CVE families and was not used to design the catalog.
> Report both numbers separately — the gap between them is the honest indicator of generalisability.

## Corpus: `benchmark/expected`

| Case | Expected | Detected (best run) | Verdict | Latency (median) | Cost (median) |
|------|----------|----------------------|---------|------------------|----------------|
| 01_dom_xss_introduction | R-02 | R-02 | TP×1 | 216ms | $0.0023 |
| 02_ssrf_allowlist_removed | B-04 | B-04 | TP×1 | 213ms | $0.0022 |
| 03_safe_refactor | — (TN expected) | — | TN | 208ms | $0.0019 |
| 04_idor_ambiguous | B-11 | B-11 | TP×1 | 214ms | $0.0022 |
| 05_sanitizer_removed | R-01 | R-01 | TP×1 | 214ms | $0.0021 |
| 06_dockerfile_root_user | D-01 | D-01 | TP×1 | 210ms | $0.0021 |
| 07_renamed_with_change | B-01 | B-01 | TP×1 | 215ms | $0.0021 |
| 08_deleted_file | — (TN expected) | — | TN | 211ms | $0.0020 |
| 09_binary_file | — (TN expected) | — | TN | 210ms | $0.0019 |

| Mode | TP | FP | FN | TN | Precision | Recall | F1 |
|------|----|----|----|----|-----------|--------|----|
| Strict (rule_id exact) | 6 | 0 | 0 | 3 | 1 | 1 | **1** |
| Loose (OWASP+CWE match) | 6 | 0 | 0 | 3 | 1 | 1 | **1** |

## Corpus: `benchmark/independent_corpus`

| Case | Expected | Detected (best run) | Verdict | Latency (median) | Cost (median) |
|------|----------|----------------------|---------|------------------|----------------|
| i01_prototype_pollution_argv_merge | R-05 | R-05 | TP×1 | 221ms | $0.0021 |
| i02_xxe_xml_parser | B-12 | B-12 | TP×1 | 214ms | $0.0021 |
| i03_command_injection_image_convert | B-02 | B-02 | TP×1 | 214ms | $0.0021 |
| i04_path_traversal_template_loader | B-05 | B-05 | TP×1 | 213ms | $0.0021 |
| i05_server_side_open_redirect | B-14 | B-14 | TP×1 | 215ms | $0.0021 |
| i06_mass_assignment_user_update | B-13 | B-13 | TP×1 | 218ms | $0.0022 |
| i07_weak_crypto_password_hash | B-07 | B-07 | TP×1 | 216ms | $0.0021 |
| i08_csrf_protection_removed | B-08 | B-08 | TP×1 | 208ms | $0.0021 |
| i09_nosql_injection_mongoose_where | B-03 | B-03 | TP×1 | 218ms | $0.0022 |
| i10_safe_helmet_added | — (TN expected) | — | TN | 217ms | $0.0020 |

| Mode | TP | FP | FN | TN | Precision | Recall | F1 |
|------|----|----|----|----|-----------|--------|----|
| Strict (rule_id exact) | 9 | 0 | 0 | 1 | 1 | 1 | **1** |
| Loose (OWASP+CWE match) | 9 | 0 | 0 | 1 | 1 | 1 | **1** |

## Corpus: `benchmark/complex_corpus`

| Case | Expected | Detected (best run) | Verdict | Latency (median) | Cost (median) |
|------|----------|----------------------|---------|------------------|----------------|
| c01_ssrf_via_extracted_helper | B-04 | B-04 | TP×1 | 215ms | $0.0022 |
| c02_compositional_xss_regression | R-01 | — | FN×1 | 220ms | $0.0022 |
| c03_authz_check_moved_breaks_semantics | B-11 | — | FN×1 | 217ms | $0.0022 |
| c04_secret_buried_in_refactor | R-07 | — | FN×1 | 215ms | $0.0022 |
| c05_cross_file_sql_injection | B-01 | B-01 | TP×1 | 218ms | $0.0022 |
| c06_safe_large_refactor | — (TN expected) | — | TN | 216ms | $0.0021 |
| c07_prototype_pollution_via_merge_util | R-05 | R-05 | TP×1 | 211ms | $0.0022 |

| Mode | TP | FP | FN | TN | Precision | Recall | F1 |
|------|----|----|----|----|-----------|--------|----|
| Strict (rule_id exact) | 3 | 0 | 3 | 1 | 1 | 0.5 | **0.667** |
| Loose (OWASP+CWE match) | 3 | 0 | 3 | 1 | 1 | 0.5 | **0.667** |

## Generalisation gaps

Each row is `(F1 of corpus A) − (F1 of corpus B)`. The expected (healthy) trend is monotonically degrading F1 from smoke → independent → complex → oss_pilot, reflecting cases drifting further from the catalog's design assumptions.

A large positive gap (>0.20) on any step signals over-fit at that level; a flat or inverted gap suggests the next corpus is too easy.

| Transition | Strict F1 (a → b) | Strict gap | Loose F1 (a → b) | Loose gap |
|------------|--------------------|-----------|-------------------|-----------|
| smoke → independent | `1` → `1` | **+0** | `1` → `1` | **+0** |
| independent → complex | `1` → `0.667` | **+0.333** | `1` → `0.667` | **+0.333** |

