# Related work and positioning

This document situates security-audit against the academic and industrial state of the art as of mid-2026. It is the literature-review counterpart to ADR-001 (diff-only analysis) and ADR-004 (catalog grounding).

## Classical static analysis

| System | Approach | Why we differ |
|---|---|---|
| **Semgrep** | Pattern-based, language-aware AST queries | File-based, no diff awareness; predefined patterns only. We are diff-focused and LLM-reasoned. |
| **CodeQL** | Datalog query over a relational AST | Whole-program data flow analysis, expensive, requires database build. We sacrifice global precision for per-PR speed and cost. |
| **Snyk Code** | Hybrid AST + ML for vulnerability detection | Whole-file analysis with proprietary models. We are diff-only, open-source, and provider-agnostic. |
| **ESLint plugin-security** | Pattern-based on JS AST | Single-language, single-vendor patterns. We cover TS/JS plus Dockerfile/compose with the same engine. |

**Where we win:** zero file-state mapping cost, no AST per language, configurable provider, attributable findings.
**Where we lose:** recall on rare or compositional patterns the catalog never describes; absolute precision on simple syntactic patterns (Semgrep wins clean here).

## LLM-based vulnerability detection (academic line of work)

### Liu, Wang, Cao et al. (2024) — *LLM-Based Vulnerability Detection in Source Code: A Systematic Review* — arXiv:2404.18186

Surveys 53 papers on applying LLMs to vulnerability detection. Key conclusions relevant to our design choices:

- **Grounding helps.** Models given a catalog or examples of vulnerability classes consistently outperform free-form classification (matches our ADR-004).
- **Whole-function inputs dominate the literature.** Few prior systems work on diffs; our diff-only emphasis is novel within this strand.
- **Calibration is under-studied.** Most papers report precision/recall on a single decision threshold; almost none ask "is the model's self-reported confidence calibrated?" — our `exploit_trace` mechanism (ADR-005) is an attempt to operationalise this.

### Khare, Dutta, Li et al. (2023) — *Understanding the Effectiveness of LLMs in Detecting Security Vulnerabilities* — arXiv:2311.16169

Benchmarks GPT-4, GPT-3.5, and CodeLlama on Java/C vulnerability datasets (Big-Vul, OWASP Benchmark). Findings we explicitly account for:

- GPT-4 achieves ~75 % precision and ~60 % recall on whole-function inputs.
- Confidence is **poorly calibrated**: the model emits "high confidence" on >50 % of FPs.
- Chain-of-thought prompting helps marginally (≈5 % F1) but doubles cost.

Our response: we lean on **structured output** + **post-hoc calibration** rather than CoT. The `exploit_trace` field is the structural equivalent of "show your work" — it costs ~20 % more tokens than CoT-free output but makes calibration mechanically enforceable.

### Steenhoek, Rahman, Roy et al. (2024) — *A Comprehensive Study of LLM Capabilities for Vulnerability Detection* — arXiv:2403.17218

Tests 11 LLMs on 7 datasets covering C, C++, Java, Python. Headline findings:

- FP rate is the **dominant** failure mode (15–35 % across models).
- Per-class accuracy varies wildly: XSS-class >80 %, race conditions <20 %.
- Adding the file's surrounding context boosts recall but does not improve precision.

Our response: we *acknowledge* the FP-dominance problem in our verdict design (`NEEDS_HUMAN` is preferred over confident `TRUE_POSITIVE` when the chain is incomplete; `FALSE_POSITIVE` verdicts are emitted explicitly). We do **not** claim better FP rates without measurement.

### Fu & Tantithamthavorn (2022) — *LineVul: Transformer-based Line-Level Vulnerability Prediction* — MSR 2022

LineVul predicts vulnerability at the **line** granularity using BERT-style encoders. It is the closest existing system to our anti-hallucination guarantee (every finding must point at a real line) — though LineVul does so via embedding similarity, while we do it via verbatim substring check in `validate_finding.mjs`.

### Russell et al. (2018) — *Automated Vulnerability Detection in Source Code Using Deep Representation Learning* — ICMLA 2018

Pre-LLM baseline using CNN/RNN on token sequences. Reports ROC-AUC ≈ 0.87 but treats vulnerability detection as binary classification (vulnerable / not). We borrow the **multi-class severity grounding** from later work; binary models cannot drive remediation routing.

## Industry LLM-augmented SAST (closed-source)

| Vendor | Public claims | Our independent assessment |
|---|---|---|
| **GitHub Copilot Autofix** | "Suggests fixes for CodeQL alerts" | Strictly post-detection. Different scope: it explains, we detect. |
| **Snyk DeepCode AI** | "AI-augmented bug detection" | Proprietary models, closed implementation. No independent benchmark. |
| **Cursor / Codeium security review** | "PR-time review with LLM" | Closed prompts, no published evaluation methodology. |
| **PRevent (Anthropic 2025 internal)** | Diff-aware PR review with Claude | Closest competitor in spirit. Closed source. |

None of the industry tools publishes their system prompt, catalog, or evaluation harness. **This project publishes all three** under MIT — making it a useful reference even where the empirical results are limited to a curated smoke set.

## What's novel in this work

Of the choices documented in ADRs 001–005, the combination most distinguishing this project from prior art:

1. **Diff-only as a primary architectural commitment.** Most LLM-SAST literature treats diffs as a special case of whole-file analysis. We invert that — full-file context is opt-in via `--include-file-context`, not the default.
2. **Catalog as versioned grounding + drift detector.** No prior open-source system enforces that every finding references a controlled vocabulary, with CI gating to prevent silent rule-id mismatches.
3. **`exploit_trace` as a calibration mechanism.** We have not found prior work that requires the LLM to enumerate source → sink → missing-guard *and* uses that structure as a post-hoc check on self-reported confidence. The mechanism is described in ADR-005.

These are research-grade claims, but **the empirical evidence is currently limited** to a 9-case smoke benchmark. Validating them on a real CVE-fix corpus (≥100 diffs) is the highest-priority future work.

## What we explicitly **do not** claim

- We do **not** claim higher precision or recall than commercial SAST tools — we have not run that comparison.
- We do **not** claim our calibration mechanism is empirically validated — only that it is mechanically sound; the evidence will come from an extended benchmark.
- We do **not** claim recall on vulnerability classes outside the catalog — A09 is excluded by design; A06 dependency CVEs are out of scope; business-logic and protocol-level flaws are likely missed.

## Reading list (full bibliography lives in the diploma appendix `sources.md`, not committed to this repository)

The four references most worth reading for someone evaluating this project:

1. **Liu et al. 2024** — for the systematic survey context.
2. **Khare et al. 2023** — for empirical calibration failure of LLMs on vulnerability detection.
3. **Steenhoek et al. 2024** — for the per-class accuracy distribution that motivates our verdict discipline.
4. **OWASP Top 10 (2021)** — for the taxonomy our catalog is grounded in.
