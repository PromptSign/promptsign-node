// Discover and verify every signable instruction artifact under given roots:
// bundle directories (.promptsign/bundle.json), sidecar-signed files
// (*.psig.json), and well-known instruction files that SHOULD be signed.

import fs from 'node:fs';
import path from 'node:path';
import { verifyTarget } from './verify.mjs';

const SKIP_DIRS = new Set(['.git', 'node_modules', '__pycache__', '.venv', '.promptsign']);
const KNOWN_FILES = new Set([
  'CLAUDE.md',
  'AGENTS.md',
  'SKILL.md',
  // OpenClaw workspace bootstrap files (also loaded by ClawPilot desktop apps).
  'SOUL.md',
  'TOOLS.md',
  'IDENTITY.md',
  'USER.md',
  'HEARTBEAT.md',
  'BOOTSTRAP.md',
  'MEMORY.md',
]);

export function discoverTargets(roots) {
  const bundleDirs = [];
  const files = [];
  const seen = new Set();

  function walk(dir) {
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    if (fs.existsSync(path.join(dir, '.promptsign', 'bundle.json'))) {
      bundleDirs.push(dir);
    }
    for (const ent of entries) {
      const abs = path.join(dir, ent.name);
      if (ent.isDirectory()) {
        if (!SKIP_DIRS.has(ent.name)) walk(abs);
      } else if (ent.isFile()) {
        const inAgentsDir = path.basename(dir) === 'agents' && /\.md$/i.test(ent.name);
        const hasSidecar = fs.existsSync(abs + '.psig.json');
        if (KNOWN_FILES.has(ent.name) || inAgentsDir || hasSidecar) {
          files.push({ abs, hasSidecar });
        }
      }
    }
  }

  for (const root of roots) {
    const abs = path.resolve(root);
    if (!fs.existsSync(abs)) continue;
    if (fs.statSync(abs).isFile())
      files.push({ abs, hasSidecar: fs.existsSync(abs + '.psig.json') });
    else walk(abs);
  }

  const targets = [];
  for (const d of bundleDirs) {
    if (!seen.has(d)) {
      seen.add(d);
      targets.push(d);
    }
  }
  const covered = (f) => bundleDirs.some((d) => f.startsWith(d + path.sep));
  for (const f of files) {
    if (seen.has(f.abs) || covered(f.abs)) continue;
    seen.add(f.abs);
    targets.push(f.abs);
  }
  return targets;
}

export function verifyTree(roots, opts = {}) {
  return discoverTargets(roots).map((t) => verifyTarget(t, opts));
}
