# Snyk / public-DB snippet corpus

Breadth supplement (spec §4.3): self-contained vulnerable JS/TS snippets from
public vulnerability databases, each turned into a one-function diff. Covers CWE
classes the full-app corpora do not exercise.

**Lower realism by design** — this corpus is a coverage breadth supplement, NOT
an external-validity claim, and is excluded from the generalisation-gap chain.

## How cases are built / provenance / validation
Same diff + `expected/` + mandatory `provenance` schema as the other corpora.
`source` cites a real public reference for the vulnerability class — a Snyk
`SNYK-JS-…` id, a CVE, or the authoritative OWASP / CWE / MDN page for the pattern.
Validate: `node scripts/validate_corpus.mjs benchmark/snyk_corpus`

## Case inventory (7 snippets)
Each case is a constructed one-function snippet (`provenance.kind: "synthesized"`)
targeting a catalog class that **no full-app corpus exercises**. All cite a real
public advisory / OWASP / CWE / MDN reference and carry the breadth-supplement
caveat. All-positive (no TN controls — those live in the Juice Shop corpus).

| id | class | rule | OWASP · CWE · sev |
|----|-------|------|-------------------|
| sn01 | `target="_blank"` without `rel="noopener"` (reverse tabnabbing) | R-03 | A02 · CWE-1022 · medium |
| sn02 | Auth token persisted in `localStorage` | R-06 | A04 · CWE-922 · high |
| sn03 | Client-side open redirect (`window.location` ← user input) | R-08 | A01 · CWE-601 · high |
| sn04 | `postMessage` handler without `event.origin` check | R-09 | A06 · CWE-346 · high |
| sn05 | External `<script>` without SRI `integrity` / missing CSP | R-10 | A02 · CWE-693 · medium |
| sn06 | Cross-origin `fetch` with `credentials:'include'` + `mode:'no-cors'` | R-11 | A02 · CWE-942 · high |
| sn07 | Hardcoded credentials in a DB connection string | B-10 | A07 · CWE-798 · critical |

These 7 close the breadth gap: rules no app corpus exercised. The corpus adds **no
new catalog rule** (all 7 classes already existed) and is **excluded from the
generalisation-gap chain** (`GAP_CHAIN`) by design — it is a coverage supplement,
not an external-validity measurement.
