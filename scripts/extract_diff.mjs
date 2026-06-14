#!/usr/bin/env node
/**
 * extract_diff.mjs — extracts a structured diff from git.
 *
 * No API calls. Pure git wrapper.
 *
 * Outputs JSON:
 *   {
 *     mode: 'against' | 'staged' | 'file',
 *     base: 'origin/main' | 'HEAD' | null,
 *     head: 'HEAD' | 'INDEX',
 *     stats: { files_changed, lines_added, lines_removed },
 *     files: [
 *       { path, old_path, status, hunks: [{ old_start, old_lines, new_start, new_lines, content }] }
 *     ]
 *   }
 *
 * Usage:
 *   node extract_diff.mjs --against=main             # diff vs origin/main (PR mode)
 *   node extract_diff.mjs --against=HEAD~1           # diff vs previous commit
 *   node extract_diff.mjs --staged                   # diff of staged changes (pre-commit mode)
 *   node extract_diff.mjs --diff=path/to/file.diff   # parse an existing diff file
 *   node extract_diff.mjs --context=10               # context lines (default 10)
 *   node extract_diff.mjs --include='**\/*.ts'        # glob include
 *   node extract_diff.mjs --exclude='**\/*.test.ts'   # glob exclude (default: tests, node_modules, dist)
 *   node extract_diff.mjs --max-files=50             # cap files
 */

import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import { parseArgs } from 'node:util';

import { globToRegex, matchesAnyGlob } from './glob.mjs';

// Re-export for back-compat: prior versions of this module owned globToRegex
// itself, and a handful of tests import it from extract_diff. Forward to the
// shared implementation so the redirected callers stay green.
export { globToRegex, matchesAnyGlob };

const DEFAULT_EXCLUDES = [
  '**/node_modules/**',
  '**/dist/**',
  '**/build/**',
  '**/coverage/**',
  '**/.next/**',
  '**/*.lock',
  '**/*.min.js',
  '**/*.snap',
];

function runGit(args, cwd = process.cwd()) {
  try {
    return execFileSync('git', args, {
      cwd,
      encoding: 'utf8',
      maxBuffer: 200 * 1024 * 1024,
    });
  } catch (e) {
    const msg = e.stderr?.toString() || e.message;
    throw new Error(`git ${args.join(' ')} failed: ${msg.trim()}`);
  }
}

function resolveBaseRef(base) {
  // Accept: 'main', 'origin/main', 'HEAD~1', commit sha. Always return concrete ref.
  if (!base) return null;
  try {
    runGit(['rev-parse', '--verify', base]);
    return base;
  } catch {
    // try with origin/ prefix
    try {
      runGit(['rev-parse', '--verify', `origin/${base}`]);
      return `origin/${base}`;
    } catch {
      throw new Error(`Could not resolve base ref: ${base}`);
    }
  }
}

/**
 * Parse unified diff text into structured form.
 *
 * @param {string} text — output of `git diff --unified=N` or an external `.diff` file
 * @returns {Array<{path: string|null, old_path: string|null, status: string,
 *   hunks: Array<{old_start: number, old_lines: number, new_start: number, new_lines: number, content: string}>}>}
 */
export function parseUnifiedDiff(text) {
  if (!text || !text.trim()) return [];

  const files = [];
  let currentFile = null;
  let currentHunk = null;

  const lines = text.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    if (line.startsWith('diff --git ')) {
      // New file block
      if (currentHunk && currentFile) currentFile.hunks.push(currentHunk);
      if (currentFile) files.push(currentFile);
      currentHunk = null;
      const m = line.match(/^diff --git a\/(.+?) b\/(.+)$/);
      currentFile = {
        path: m ? m[2] : null,
        old_path: m ? m[1] : null,
        status: 'modified',
        hunks: [],
      };
      continue;
    }

    if (!currentFile) continue;

    if (line.startsWith('new file mode')) {
      currentFile.status = 'added';
      continue;
    }
    if (line.startsWith('deleted file mode')) {
      currentFile.status = 'deleted';
      continue;
    }
    if (line.startsWith('rename from ')) {
      currentFile.status = 'renamed';
      currentFile.old_path = line.slice('rename from '.length).trim();
      continue;
    }
    if (line.startsWith('rename to ')) {
      currentFile.path = line.slice('rename to '.length).trim();
      continue;
    }
    if (line.startsWith('--- ') || line.startsWith('+++ ')) {
      // file path headers; we already have them from `diff --git`
      continue;
    }
    if (line.startsWith('index ') || line.startsWith('similarity index ')) {
      continue;
    }
    if (line.startsWith('Binary files ')) {
      currentFile.status = 'binary';
      continue;
    }

    if (line.startsWith('@@')) {
      // Hunk header: @@ -old_start,old_lines +new_start,new_lines @@ optional-context
      if (currentHunk && currentFile) currentFile.hunks.push(currentHunk);
      const m = line.match(/^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@/);
      if (!m) continue;
      currentHunk = {
        old_start: parseInt(m[1], 10),
        old_lines: m[2] ? parseInt(m[2], 10) : 1,
        new_start: parseInt(m[3], 10),
        new_lines: m[4] ? parseInt(m[4], 10) : 1,
        content: line + '\n',
      };
      continue;
    }

    if (currentHunk) {
      currentHunk.content += line + '\n';
    }
  }

  if (currentHunk && currentFile) currentFile.hunks.push(currentHunk);
  if (currentFile) files.push(currentFile);

  return files;
}

export function filterFiles(files, includes, excludes) {
  return files.filter(f => {
    if (!f.path) return false;
    if (matchesAnyGlob(f.path, excludes)) return false;
    if (includes.length === 0) return true;
    return matchesAnyGlob(f.path, includes);
  });
}

export function computeStats(files) {
  let lines_added = 0;
  let lines_removed = 0;
  for (const f of files) {
    for (const h of f.hunks) {
      for (const l of h.content.split('\n')) {
        if (l.startsWith('+') && !l.startsWith('+++')) lines_added++;
        else if (l.startsWith('-') && !l.startsWith('---')) lines_removed++;
      }
    }
  }
  return { files_changed: files.length, lines_added, lines_removed };
}

function getDiffText({ against, staged, diffFile, context }) {
  if (diffFile) {
    return { mode: 'file', base: null, head: null, text: fs.readFileSync(diffFile, 'utf8') };
  }
  if (staged) {
    const text = runGit(['diff', '--cached', `--unified=${context}`]);
    return { mode: 'staged', base: 'INDEX', head: 'WORKING', text };
  }
  if (against) {
    const base = resolveBaseRef(against);
    const text = runGit(['diff', `${base}...HEAD`, `--unified=${context}`]);
    return { mode: 'against', base, head: 'HEAD', text };
  }
  throw new Error('Must specify one of: --against=<ref>, --staged, --diff=<file>');
}

function main() {
  const { values } = parseArgs({
    options: {
      against: { type: 'string' },
      staged: { type: 'boolean', default: false },
      diff: { type: 'string' },
      context: { type: 'string', default: '10' },
      include: { type: 'string', multiple: true, default: [] },
      exclude: { type: 'string', multiple: true, default: [] },
      'include-file-context': { type: 'boolean', default: false },
      'max-files': { type: 'string', default: '50' },
      help: { type: 'boolean', default: false },
    },
    strict: true,
  });

  if (values.help) {
    console.log(fs.readFileSync(new URL(import.meta.url), 'utf8').match(/\/\*\*[\s\S]*?\*\//)[0]);
    process.exit(0);
  }

  const context = parseInt(values.context, 10);
  const maxFiles = parseInt(values['max-files'], 10);
  const excludes = [...DEFAULT_EXCLUDES, ...(values.exclude || [])];
  const includes = values.include || [];

  const { mode, base, head, text } = getDiffText({
    against: values.against,
    staged: values.staged,
    diffFile: values.diff,
    context,
  });

  let files = parseUnifiedDiff(text);
  files = filterFiles(files, includes, excludes);
  if (files.length > maxFiles) {
    process.stderr.write(`extract_diff: capping to ${maxFiles} files (had ${files.length}). Use --max-files to override.\n`);
    files = files.slice(0, maxFiles);
  }

  // --include-file-context: attach the full new-side content of each modified
  // file. Useful when a vulnerability depends on state defined outside the
  // hunk's surrounding context (e.g. a sanitizer imported but not called in
  // the diff). For binary / deleted files we skip the read.
  if (values['include-file-context']) {
    if (mode === 'file') {
      // External `.diff` files have no associated git tree we can resolve, so
      // there's nothing to fetch full file content from. Warn explicitly so a
      // user who set the flag understands why their prompt isn't enlarged.
      process.stderr.write(
        'extract_diff: --include-file-context has no effect with --diff=<file> ' +
        '(no git tree available). Use --against=<ref> or --staged instead.\n'
      );
    } else {
      for (const f of files) {
        if (!f.path) continue;
        if (f.status === 'binary' || f.status === 'deleted') continue;
        try {
          // For staged mode we read the index version (`:path`); otherwise HEAD.
          const ref = mode === 'staged' ? `:${f.path}` : `HEAD:${f.path}`;
          const content = runGit(['show', ref]);
          // Cap full-file context to keep prompt size sane on huge files. The
          // model rarely needs more than ~12K chars (~3K tokens) of surrounding
          // context to disambiguate; bigger files just balloon the prompt.
          const MAX_FILE_CHARS = 12_000;
          f.full_content = content.length > MAX_FILE_CHARS
            ? content.slice(0, MAX_FILE_CHARS) + `\n... [truncated ${content.length - MAX_FILE_CHARS} chars]`
            : content;
        } catch {
          // New file or git can't resolve — skip silently rather than fail.
        }
      }
    }
  }

  const stats = computeStats(files);

  const out = {
    schema_version: '1.0',
    extracted_at: new Date().toISOString(),
    mode,
    base,
    head,
    stats,
    files,
  };

  process.stdout.write(JSON.stringify(out, null, 2) + '\n');
}

if (import.meta.url === `file://${process.argv[1]}`) main();
