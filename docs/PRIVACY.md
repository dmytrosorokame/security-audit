# Privacy and data handling

This document is for security teams and DPOs evaluating whether to deploy security-audit. It states **what data leaves the boundary, to whom, and with what guarantees** — in concrete terms, not marketing prose.

## What we send to the LLM provider

For every scan, the tool sends to the configured provider (Anthropic or OpenAI):

| Field | Origin | Persisted on our side? |
|---|---|---|
| The **diff content** (`+` / `-` lines plus context) | the PR or staged commit | Only in the file cache (`--cache-dir`, default `.security-audit-cache/`), with secrets pre-redacted |
| Repository file **paths** | the diff | Cache only, see above |
| The **system prompt** + **OWASP catalog** + **few-shot examples** | this repo | Never |
| Optional **full-file content** when `--include-file-context` is set | git tree, capped at 12 KB per file | Cache only, with secrets pre-redacted |

We do **not** send: branch names, commit messages, author identities, repo metadata, environment variables, or anything outside the diff.

## What we do **not** send

- Other files in the working tree (unless `--include-file-context` and they had a hunk).
- `.env`, secrets, configuration files outside the diff.
- The output of any previous scan.
- Telemetry / usage data / opt-in beacons — we ship none.

## Where the data goes

The provider you choose. Their terms apply:

- **Anthropic.** API inputs/outputs are retained per Anthropic's commercial terms. As of 2026-05, default retention is 30 days for abuse monitoring; opt-in to longer-retention "Zero retention" requires a separate contract. See <https://www.anthropic.com/legal/privacy>.
- **OpenAI.** API inputs/outputs are not used to train models (under the default API terms, not ChatGPT terms). Default retention is 30 days. See <https://platform.openai.com/docs/data-controls>.

If your security policy says "source code may not leave the corporate boundary" — neither provider satisfies that. Wait for the self-hosted (Ollama / vLLM) provider, planned for a future release; or run the tool in a sandbox network that talks only to your own LLM endpoint.

## Secrets in the diff

If the diff contains a secret (committed-and-then-rotated key, leaked Stripe live key, etc.), the secret **does reach the LLM provider** — the model needs to see it to flag it. Mitigations applied locally:

1. The secret is matched by `SECRET_PATTERNS` (`validate_finding.mjs`) and replaced with `<REDACTED:LABEL>` in `evidence`, `rationale`, `remediation`.
2. This happens **before** the finding is serialised to *any* destination: terminal, PR comment, SARIF report, or the local file cache.
3. Therefore: the GitHub PR comment, the Code Scanning entry, and the `.security-audit-cache/` directory contain only the placeholder, not the live secret.

The secret still appears, momentarily, in:
- The provider's request log (visible to the provider for their retention window).
- Memory of the running process for the duration of one scan.

If a secret reaches the provider's logs and you need it purged, contact your provider directly with the request ID.

## Cache file format

Each entry is a JSON document containing the redacted LLM response. Cache key is `sha256(provider | model | grounding_hash | diff_content_hash)`. TTL is 24 hours; expired entries are ignored on read but not auto-deleted (clean up with `rm -rf .security-audit-cache/` or via cron).

The cache is a **plaintext file on disk**. Treat its directory's permissions accordingly — if multiple users share a host, scope it to a per-user path:

```bash
node scripts/scan_diff.mjs --cache-dir="$HOME/.cache/security-audit/<repo>"
```

## Compliance notes

- **GDPR / ДСТУ ISO/IEC 27001.** Source code is not personal data unless it explicitly contains PII. If your diffs contain real PII (e.g., a hard-coded test user's email or phone number) you are subject to the same disclosure obligations as any code review tool that processes that code.
- **Sectoral regulation (PCI-DSS, HIPAA).** Sending regulated data to a third-party LLM provider typically requires a Business Associate Agreement or equivalent. Do not deploy security-audit on a repo that may contain CHD, PHI, or similar without contractual clearance from the provider.
- **Export control.** The diff content may contain cryptographic implementation details. Confirm with your legal team that sending those to a US-based LLM provider is permitted in your jurisdiction.

## How to disable specific data flows

| To suppress… | Use… |
|---|---|
| Sending the entire diff to a remote LLM | Self-hosted provider (roadmap). Until then, do not deploy this tool. |
| Persisting cache entries to disk | `--no-cache` or `--cache-dir=none` |
| Sending full-file content beyond the hunk | Default — `--include-file-context` is **opt-in** |
| Posting the report to the PR comment | `--format=cli` and pipe stdout to `/dev/null` (the Action wraps `--format=pr`; replace its step) |
| Uploading SARIF to GitHub Code Scanning | Remove the `github/codeql-action/upload-sarif` step from your workflow |

## Reporting concerns

If you discover that our tool sends data we don't list above, that's a security-relevant defect. Report via [SECURITY.md](../SECURITY.md).
