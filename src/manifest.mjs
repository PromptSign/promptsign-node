// Bundle manifest construction and integrity re-verification.
// The manifest — not any individual file — is the unit of signing (spec/01-manifest.md).

import fs from 'node:fs';
import path from 'node:path';
import {
  CanonError,
  digestFile,
  sha256,
  canonicalizeMarkdown,
  isMarkdown,
} from './canonicalize.mjs';

export const MANIFEST_SCHEMA = 'promptsign/manifest/v1';

const SKIP_DIRS = new Set([
  '.promptsign',
  '.git',
  'node_modules',
  '__pycache__',
  '.venv',
  '.in_use',
]);
// Host-owned bookkeeping files that the Claude Code runtime writes into a
// versioned plugin cache directory after install. The publisher does not own
// them, and they are not part of the signed artifact. See spec/01-manifest.md
// "Host-owned bookkeeping" for the full, closed list. This is not a
// signer-controlled exclusion: it changes only when the runtime's own
// bookkeeping set changes.
const SKIP_FILES = new Set(['.orphaned_at']);
const EXEC_EXTS = new Set([
  '.py',
  '.sh',
  '.bash',
  '.zsh',
  '.js',
  '.mjs',
  '.cjs',
  '.ts',
  '.ps1',
  '.psm1',
  '.cmd',
  '.bat',
  '.exe',
  '.rb',
  '.pl',
  '.php',
]);
const ENTRYPOINTS = new Set([
  'SKILL.md',
  'CLAUDE.md',
  'AGENTS.md',
  // OpenClaw workspace bootstrap files (also loaded by ClawPilot desktop apps).
  'SOUL.md',
  'TOOLS.md',
  'IDENTITY.md',
  'USER.md',
  'HEARTBEAT.md',
  'BOOTSTRAP.md',
  'MEMORY.md',
]);
// Files an agent injects into model context verbatim (whole-file). An embedded
// x-promptsign: marker in these must never masquerade as a signature: refused
// on sign, unconditional failure on verify (see spec/03-bundle.md). Covers
// Claude Code / Codex plus the OpenClaw workspace bootstrap set.
export const CONTEXT_INJECTED = new Set([
  'CLAUDE.md',
  'AGENTS.md',
  'SOUL.md',
  'TOOLS.md',
  'IDENTITY.md',
  'USER.md',
  'HEARTBEAT.md',
  'BOOTSTRAP.md',
  'MEMORY.md',
]);

export function isSidecar(name) {
  return name.endsWith('.psig.json');
}

export function roleFor(relPath) {
  if (!relPath.includes('/') && ENTRYPOINTS.has(relPath)) return 'entrypoint';
  const ext = path.posix.extname(relPath).toLowerCase();
  if (EXEC_EXTS.has(ext) || relPath.split('/')[0] === 'scripts') return 'executable';
  return 'reference';
}

function walk(root, rel = '') {
  const out = [];
  const abs = rel ? path.join(root, rel) : root;
  for (const ent of fs.readdirSync(abs, { withFileTypes: true })) {
    const relChild = rel ? `${rel}/${ent.name}` : ent.name;
    if (ent.isDirectory()) {
      if (SKIP_DIRS.has(ent.name)) continue;
      out.push(...walk(root, relChild));
    } else if (ent.isFile()) {
      if (isSidecar(ent.name) || SKIP_FILES.has(ent.name)) continue;
      out.push(relChild);
    }
  }
  return out.sort();
}

// Sorted relative paths of every signable file under root (skip dirs and
// sidecars excluded) — the same walk buildManifest and checkIntegrity use.
export function walkFiles(root) {
  return walk(root);
}

// Best-effort read of top-level `name:` / `version:` from the entrypoint's YAML
// frontmatter, so a signed skill/agent carries its real name and version instead
// of the basename and 0.0.0 placeholder. Metadata convenience for the default
// only (an explicit --name/--version wins) — never consulted on verify.
function entrypointFrontmatter(root, scope, relPaths) {
  let rel = null;
  if (scope === 'file') rel = relPaths[0];
  else
    for (const name of ENTRYPOINTS)
      if (relPaths.includes(name)) {
        rel = name;
        break;
      }
  if (!rel) return {};
  let text;
  try {
    text = fs.readFileSync(path.join(root, ...rel.split('/'))).toString('utf8', 0, 4096);
  } catch {
    return {};
  }
  const block = /^\uFEFF?---\r?\n([\s\S]*?)\r?\n---/.exec(text);
  if (!block) return {};
  const out = {};
  for (const line of block[1].split(/\r?\n/)) {
    const kv = /^(name|version)\s*:\s*(.+?)\s*$/i.exec(line);
    if (!kv) continue;
    const key = kv[1].toLowerCase();
    const v = kv[2].replace(/^["']|["']$/g, '').trim();
    if (v && !(key in out)) out[key] = v;
  }
  return out;
}

export function inferKind(root, relPaths) {
  if (relPaths.includes('SKILL.md')) return 'skill';
  if (relPaths.some((p) => p.startsWith('commands/'))) return 'command';
  if (relPaths.length === 1) {
    const base = path.posix.basename(relPaths[0]);
    if (CONTEXT_INJECTED.has(base)) return 'instructions';
    if (isMarkdown(base)) return 'agent';
  }
  return 'file';
}

function fileEntry(root, relPath) {
  const role = roleFor(relPath);
  const buf = fs.readFileSync(path.join(root, ...relPath.split('/')));
  try {
    return { path: relPath, sha256: digestFile(buf, relPath, role), role };
  } catch (e) {
    if (e instanceof CanonError) throw new CanonError(`${relPath}: ${e.message}`);
    throw e;
  }
}

// scope "dir": manifest covers an entire bundle directory (extra files = failure).
// scope "file": manifest covers a single standalone file with a sidecar signature.
export function buildManifest({ root, singleFile, name, version, kind }) {
  let relPaths;
  let scope;
  if (singleFile) {
    relPaths = [path.basename(singleFile)];
    scope = 'file';
  } else {
    relPaths = walk(root);
    scope = 'dir';
    if (relPaths.length === 0) throw new Error(`no files to sign under ${root}`);
  }
  const files = relPaths.map((p) => {
    const entry = fileEntry(root, p);
    if (scope === 'file' && isMarkdown(p)) entry.role = 'entrypoint';
    return entry;
  });
  const fm = entrypointFrontmatter(root, scope, relPaths);
  return {
    schema: MANIFEST_SCHEMA,
    name:
      name ||
      fm.name ||
      path.basename(singleFile ? singleFile : root).replace(/\.(md|markdown)$/i, ''),
    version: version || fm.version || '0.0.0',
    kind: kind || inferKind(root, relPaths),
    scope,
    created: new Date().toISOString(),
    files,
  };
}

// Recompute digests from disk and compare against a verified manifest.
// Returns a list of problems (empty = intact).
export function checkIntegrity(root, manifest) {
  const problems = [];
  const listed = new Map(manifest.files.map((f) => [f.path, f]));
  for (const [relPath, entry] of listed) {
    if (relPath.includes('..') || path.posix.isAbsolute(relPath)) {
      problems.push(`manifest lists suspicious path: ${relPath}`);
      continue;
    }
    const abs = path.join(root, ...relPath.split('/'));
    if (!fs.existsSync(abs)) {
      problems.push(`missing file: ${relPath}`);
      continue;
    }
    let actual;
    try {
      actual = fileEntry(root, relPath);
    } catch (e) {
      problems.push(`${e.message}`);
      continue;
    }
    if (actual.sha256 !== entry.sha256) problems.push(`modified: ${relPath}`);
  }
  if (manifest.scope !== 'file') {
    for (const onDisk of walk(root)) {
      if (!listed.has(onDisk)) problems.push(`unlisted file present: ${onDisk}`);
    }
  }
  return problems;
}

export { sha256, canonicalizeMarkdown };
