/**
 * version.mjs — single source of truth for the tool version.
 *
 * Reads `version` from package.json at load time so every emitter (scan_diff
 * empty-report, llm_analyze response, format_sarif fallback) reports the
 * same string. Without this the three sites drift — and they did: 0.1.0 was
 * hardcoded in three files long after package.json moved to 0.2.0, with the
 * effect that PR comments and SARIF dedupe fingerprints carried a stale tag.
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PKG_PATH = path.resolve(__dirname, '..', 'package.json');

let _version = null;
function readVersion() {
  if (_version) return _version;
  try {
    const pkg = JSON.parse(fs.readFileSync(PKG_PATH, 'utf8'));
    _version = pkg.version || '0.0.0';
  } catch {
    // Package.json unreadable (unusual — would only happen in an archive
    // that excluded it). Fall back to a sentinel so downstream code keeps
    // working rather than throwing in a logging path.
    _version = '0.0.0';
  }
  return _version;
}

export const TOOL_NAME = 'security-audit';
export const TOOL_VERSION = readVersion();
