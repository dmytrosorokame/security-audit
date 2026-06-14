# Report Schema

The skill emits its report in two formats: human-readable Markdown and machine-readable JSON.

## JSON schema (machine-readable)

```jsonc
{
  "schema_version": "1.0",
  "target": "apps/builder-host",
  "scanned_at": "2026-05-03T18:30:00Z",
  "tool": {
    "name": "security-audit",
    "version": "0.1.0"
  },
  "summary": {
    "total": 42,
    "by_severity": { "critical": 1, "high": 8, "medium": 15, "low": 12, "info": 6 },
    "by_owasp": { "A01": 1, "A04": 2, "A05": 12, "A02": 18, "A03": 4, "A07": 1, "A08": 4 }
  },
  "findings": [
    {
      "id": "F-0001",
      "rule_id": "R-01",
      "owasp_id": "A05",
      "cwe_id": "CWE-79",
      "severity": "high",
      "confidence": "high",
      "risk_score": 7.4,
      "verdict": "TRUE_POSITIVE",
      "file": "apps/website/src/components/RichText.tsx",
      "line": 42,
      "column": 12,
      "evidence": "<div dangerouslySetInnerHTML={{__html: post.body}} />",
      "context": "post.body comes from GraphQL query without sanitization",
      "remediation": "Wrap post.body with DOMPurify.sanitize() before passing to dangerouslySetInnerHTML.",
      "references": [
        "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
        "https://cwe.mitre.org/data/definitions/79.html"
      ]
    }
  ]
}
```

## Markdown schema (human-readable)

```markdown
# Security Audit Report

**Target**: `apps/builder-host`
**Scanned at**: 2026-05-03T18:30:00Z
**Tool**: security-audit v0.1.0

## Summary

| Severity | Count |
|---------|-------|
| Critical | 1 |
| High | 8 |
| Medium | 15 |
| Low | 12 |
| Info | 6 |
| **Total** | **42** |

### By OWASP Category

| OWASP | Count | Description |
|-------|-------|-------------|
| A05 | 12 | Injection |
| A02 | 18 | Security Misconfiguration |
| ... | ... | ... |

## Top Risks

1. **[CRITICAL]** Hard-coded Stripe live key in `apps/website/src/payments/config.ts:8` (R-07, A07, CWE-798)
2. **[HIGH]** DOM XSS via `dangerouslySetInnerHTML` in `apps/website/src/components/RichText.tsx:42` (R-01, A05, CWE-79)
3. ...

## Detailed Findings

### F-0001 — DOM XSS via `dangerouslySetInnerHTML`

- **Rule**: R-01
- **OWASP**: A05 (Injection) | **CWE**: CWE-79
- **Severity**: high | **Confidence**: high | **Risk Score**: 7.4 / 10
- **Verdict**: TRUE_POSITIVE
- **Location**: `apps/website/src/components/RichText.tsx:42:12`

**Evidence**:
```tsx
<div dangerouslySetInnerHTML={{__html: post.body}} />
```

**Context**: `post.body` comes from the GraphQL `getPost` query and is not sanitised.

**Remediation**:
```tsx
import DOMPurify from 'isomorphic-dompurify';
<div dangerouslySetInnerHTML={{__html: DOMPurify.sanitize(post.body)}} />
```

**References**:
- OWASP XSS Prevention Cheat Sheet
- CWE-79
```

## Verdict legend

| Verdict | Meaning |
|---------|---------|
| `TRUE_POSITIVE` | Real vulnerability, needs a fix. |
| `LIKELY_TP` | Highly likely vulnerability; brief manual review recommended. |
| `NEEDS_HUMAN` | Context in the diff is insufficient for an automatic verdict. |
| `FALSE_POSITIVE` | Pattern matches but the context is safe (test code, static values). |
