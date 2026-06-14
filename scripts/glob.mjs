/**
 * glob.mjs — single implementation of gitignore-style glob to regex.
 *
 * Was duplicated in extract_diff.mjs and suppression.mjs; the two copies
 * drifted on edge cases (one had the doublestar-slash zero-or-more fix,
 * the other didn't). Centralising removes the drift risk: any new pattern
 * needs one fix, one test surface, one place to read.
 *
 * Supported syntax:
 *   *      one segment, no slashes
 *   **     any depth (greedy `.*`)
 *   ** /   (without the space) — zero or more path segments, so a
 *          `** /foo` pattern matches `foo` at the root too
 *   ?      one non-slash character
 *   {a,b}  alternation (literal pieces only; nested braces not supported)
 *
 * Anchored at both ends; callers don't need to add `^...$`.
 */

/**
 * @param {string} glob
 * @returns {RegExp}
 */
export function globToRegex(glob) {
  let re = '^';
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i];
    if (c === '*') {
      if (glob[i + 1] === '*' && glob[i + 2] === '/') {
        // Doublestar-slash matches zero or more path segments. The naive
        // `.*\/` expansion forces at least one leading char + slash, so a
        // pattern starting with doublestar-slash would miss top-level
        // names — exactly the gitignore behaviour users expect.
        // Group as optional to recover that case.
        re += '(?:.*\\/)?';
        i += 2;
      } else if (glob[i + 1] === '*') {
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

/**
 * Does `filePath` match any glob in the list? Returns false on empty list
 * so callers can pass an unfiltered set directly.
 *
 * @param {string} filePath
 * @param {string[]} globs
 * @returns {boolean}
 */
export function matchesAnyGlob(filePath, globs) {
  return globs.some(g => globToRegex(g).test(filePath));
}
