import { describe, it, expect } from 'vitest';
import {
  parseUnifiedDiff,
  globToRegex,
  matchesAnyGlob,
  filterFiles,
  computeStats,
} from '../extract_diff.mjs';

describe('parseUnifiedDiff', () => {
  it('returns [] on empty input', () => {
    expect(parseUnifiedDiff('')).toEqual([]);
    expect(parseUnifiedDiff('   ')).toEqual([]);
  });

  it('parses a single-file unified diff', () => {
    const diff = `diff --git a/src/foo.ts b/src/foo.ts
index 1111111..2222222 100644
--- a/src/foo.ts
+++ b/src/foo.ts
@@ -1,3 +1,4 @@
 const a = 1;
+const b = 2;
 const c = 3;
 const d = 4;
`;
    const files = parseUnifiedDiff(diff);
    expect(files).toHaveLength(1);
    expect(files[0].path).toBe('src/foo.ts');
    expect(files[0].status).toBe('modified');
    expect(files[0].hunks).toHaveLength(1);
    expect(files[0].hunks[0].new_start).toBe(1);
    expect(files[0].hunks[0].new_lines).toBe(4);
  });

  it('marks added files with status "added"', () => {
    const diff = `diff --git a/new.ts b/new.ts
new file mode 100644
index 0000000..1234567
--- /dev/null
+++ b/new.ts
@@ -0,0 +1,1 @@
+console.log("hi");
`;
    const files = parseUnifiedDiff(diff);
    expect(files[0].status).toBe('added');
  });

  it('marks deleted files with status "deleted"', () => {
    const diff = `diff --git a/old.ts b/old.ts
deleted file mode 100644
--- a/old.ts
+++ /dev/null
@@ -1,1 +0,0 @@
-console.log("bye");
`;
    const files = parseUnifiedDiff(diff);
    expect(files[0].status).toBe('deleted');
  });

  it('marks renamed files and captures both paths', () => {
    const diff = `diff --git a/old/foo.ts b/new/foo.ts
similarity index 100%
rename from old/foo.ts
rename to new/foo.ts
`;
    const files = parseUnifiedDiff(diff);
    expect(files[0].status).toBe('renamed');
    expect(files[0].old_path).toBe('old/foo.ts');
    expect(files[0].path).toBe('new/foo.ts');
  });

  it('marks binary files', () => {
    const diff = `diff --git a/img.png b/img.png
Binary files a/img.png and b/img.png differ
`;
    const files = parseUnifiedDiff(diff);
    expect(files[0].status).toBe('binary');
  });

  it('parses multiple files in one diff', () => {
    const diff = `diff --git a/a.ts b/a.ts
--- a/a.ts
+++ b/a.ts
@@ -1,1 +1,1 @@
-const a = 1;
+const a = 2;
diff --git a/b.ts b/b.ts
--- a/b.ts
+++ b/b.ts
@@ -1,1 +1,1 @@
-const b = 1;
+const b = 2;
`;
    const files = parseUnifiedDiff(diff);
    expect(files.map(f => f.path)).toEqual(['a.ts', 'b.ts']);
  });

  it('parses multiple hunks in one file', () => {
    const diff = `diff --git a/foo.ts b/foo.ts
--- a/foo.ts
+++ b/foo.ts
@@ -1,1 +1,1 @@
-const a = 1;
+const a = 2;
@@ -10,1 +10,1 @@
-const b = 1;
+const b = 2;
`;
    const files = parseUnifiedDiff(diff);
    expect(files[0].hunks).toHaveLength(2);
    expect(files[0].hunks[0].new_start).toBe(1);
    expect(files[0].hunks[1].new_start).toBe(10);
  });
});

describe('globToRegex', () => {
  it('matches a literal path', () => {
    expect(globToRegex('src/foo.ts').test('src/foo.ts')).toBe(true);
    expect(globToRegex('src/foo.ts').test('src/bar.ts')).toBe(false);
  });

  it('* matches within a path segment but not across slashes', () => {
    const re = globToRegex('src/*.ts');
    expect(re.test('src/foo.ts')).toBe(true);
    expect(re.test('src/sub/foo.ts')).toBe(false);
  });

  it('** matches across slashes', () => {
    const re = globToRegex('**/*.ts');
    expect(re.test('foo.ts')).toBe(true);
    expect(re.test('src/foo.ts')).toBe(true);
    expect(re.test('src/sub/foo.ts')).toBe(true);
  });

  it('? matches a single non-slash char', () => {
    const re = globToRegex('a?.ts');
    expect(re.test('ab.ts')).toBe(true);
    expect(re.test('abc.ts')).toBe(false);
  });

  it('{a,b} alternation works', () => {
    const re = globToRegex('*.{ts,tsx}');
    expect(re.test('foo.ts')).toBe(true);
    expect(re.test('foo.tsx')).toBe(true);
    expect(re.test('foo.js')).toBe(false);
  });

  it('escapes regex meta characters', () => {
    const re = globToRegex('a.b+c');
    // dot and plus should be literal
    expect(re.test('a.b+c')).toBe(true);
    expect(re.test('aXb+c')).toBe(false);
  });
});

describe('matchesAnyGlob', () => {
  it('returns true if any glob matches', () => {
    expect(matchesAnyGlob('src/foo.test.ts', ['**/*.test.ts', '**/*.spec.ts'])).toBe(true);
  });

  it('returns false if no glob matches', () => {
    expect(matchesAnyGlob('src/foo.ts', ['**/*.test.ts'])).toBe(false);
  });

  it('returns false for empty glob list', () => {
    expect(matchesAnyGlob('any.ts', [])).toBe(false);
  });
});

describe('filterFiles', () => {
  const files = [
    { path: 'src/main.ts', hunks: [] },
    { path: 'src/main.test.ts', hunks: [] },
    { path: 'node_modules/foo/index.js', hunks: [] },
    { path: 'docs/readme.md', hunks: [] },
  ];

  it('excludes files matching exclude globs', () => {
    const out = filterFiles(files, [], ['**/*.test.ts', '**/node_modules/**']);
    expect(out.map(f => f.path)).toEqual(['src/main.ts', 'docs/readme.md']);
  });

  it('with no includes, keeps everything not excluded', () => {
    const out = filterFiles(files, [], []);
    expect(out).toHaveLength(4);
  });

  it('with includes set, only files matching include AND not excluded are kept', () => {
    const out = filterFiles(files, ['src/**/*.ts'], ['**/*.test.ts']);
    expect(out.map(f => f.path)).toEqual(['src/main.ts']);
  });

  it('drops files with null path', () => {
    const out = filterFiles([{ path: null, hunks: [] }, ...files], [], []);
    expect(out).toHaveLength(4);
  });
});

describe('computeStats', () => {
  it('counts + and - lines, skipping +++/--- headers', () => {
    const files = [
      {
        path: 'a.ts',
        hunks: [
          {
            content: '@@ -1,2 +1,3 @@\n const a = 1;\n+const b = 2;\n+const c = 3;\n-const d = 4;\n',
          },
        ],
      },
    ];
    expect(computeStats(files)).toEqual({ files_changed: 1, lines_added: 2, lines_removed: 1 });
  });

  it('handles zero changes', () => {
    expect(computeStats([])).toEqual({ files_changed: 0, lines_added: 0, lines_removed: 0 });
  });
});
