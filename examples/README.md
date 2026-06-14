# examples/

Hand-crafted reference diffs that exercise the analyzer end-to-end. Each diff is a "what does security-audit say about this PR?" probe.

| File | Pattern | Expected verdict |
|------|---------|------------------|
| `01_dom_xss_introduction.diff` | DOM XSS via `innerHTML` (replaces safe `<p>{text}</p>` with `el.innerHTML = userText`) | **R-02** · A05 · CWE-79 · TRUE_POSITIVE · high |
| `02_ssrf_allowlist_removed.diff` | SSRF — allowlist removed; user-controlled URL fed to `axios.get` | **B-04** · A01 · CWE-918 · TRUE_POSITIVE · high |
| `03_safe_refactor.diff` | Date formatting change with no security implications | **no findings** |
| `04_idor_ambiguous.diff` | New POST route updates by URL `:id` with no visible authz check | **B-11** · A01 · CWE-639 · NEEDS_HUMAN · high (depends on middleware not shown) |
| `05_sanitizer_removed.diff` | DOMPurify call removed from a Markdown renderer; raw HTML now in `dangerouslySetInnerHTML` | **R-01** · A05 · CWE-79 · TRUE_POSITIVE · high |

## Use

```bash
# Single diff
node scripts/scan_diff.mjs --diff=examples/01_dom_xss_introduction.diff

# Force a model
node scripts/scan_diff.mjs --diff=examples/02_ssrf_allowlist_removed.diff --model=haiku

# Dry-run (no API call)
node scripts/scan_diff.mjs --diff=examples/03_safe_refactor.diff --dry-run
```

These doubles as smoke tests during development and as the seed corpus for the benchmark (see `benchmark/`).
