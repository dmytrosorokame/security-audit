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
import path from 'node:path';
import { parseArgs } from 'node:util';

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
 * Returns: [{ path, old_path, status, hunks: [{old_start, old_lines, new_start, new_lines, content}] }]
 */
function parseUnifiedDiff(text) {
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

/**
 * Glob-style match. Lightweight (no minimatch dep).
 * Supports: *, **, single-char ?, {a,b} alternatives.
 */
function globToRegex(glob) {
  let re = '^';
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i];
    if (c === '*') {
      if (glob[i + 1] === '*') {
        re += '.*';
        i++;
      } else {
        re += '[^/]*';
      }
    } else if (c === '?') {
      re += '[^/]';
    } else if (c === '{') {
      const end = glob.indexOf('}', i);
      if (end === -1) {
        re += '\\{';
      } else {
        const alts = glob.slice(i + 1, end).split(',').map(a => a.replace(/[.+^$()|[\]\\]/g, '\\$&'));
        re += '(' + alts.join('|') + ')';
        i = end;
      }
    } else if ('.+^$()|[]\\'.includes(c)) {
      re += '\\' + c;
    } else {
      re += c;
    }
  }
  re += '$';
  return new RegExp(re);
}

function matchesAnyGlob(filePath, globs) {
  return globs.some(g => globToRegex(g).test(filePath));
}

function filterFiles(files, includes, excludes) {
  return files.filter(f => {
    if (!f.path) return false;
    if (matchesAnyGlob(f.path, excludes)) return false;
    if (includes.length === 0) return true;
    return matchesAnyGlob(f.path, includes);
  });
}

function computeStats(files) {
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

main();
