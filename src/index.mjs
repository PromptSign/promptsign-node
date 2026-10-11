#!/usr/bin/env node
// promptsign — sign and verify AI instruction files (SKILL.md, AGENTS.md,
// CLAUDE.md, agent definitions). Zero-dependency reference implementation.
// Exit codes: 0 = ok (possibly with warnings), 1 = usage/internal error,
// 2 = enforcement failure (hook-friendly: Claude Code/Codex block on exit 2).

import fs from 'node:fs';
import path from 'node:path';
import { parseArgs } from 'node:util';
import { buildManifest } from './manifest.mjs';
import { signManifest, writeBundle } from './bundle.mjs';
import {
  keygen,
  loadPrivateKey,
  defaultKeyPath,
  defaultIdentity,
  promptsignHome,
} from './keys.mjs';
import { DEFAULT_POLICY, loadPolicy, loadPins, savePins } from './policy.mjs';
import { verifyTarget } from './verify.mjs';
import { verifyTree } from './verifytree.mjs';
import { DEFAULT_ROOT } from './trustroot.mjs';
import * as trust from './trustcmd.mjs';
import crypto from 'node:crypto';

const VERSION = '0.1.0';

const USAGE = `promptsign-reference ${VERSION} — PKI signing for AI instruction files

Usage:
  promptsign-reference keygen [--identity <id>] [--force]
  promptsign-reference sign <dir|file> [--name n] [--version v] [--kind k] [--identity id] [--key path]
  promptsign-reference verify <dir|file> [--policy path] [--json] [--no-pin-updates]
  promptsign-reference verify-tree <root>... [--policy path] [--json] [--quiet]
  promptsign-reference policy init [--global]
  promptsign-reference pin list | pin rm <name>
  promptsign-reference trust fetch [--force] [<bundle>] | trust show
  promptsign-reference trust add <name> --ca <pem> | trust add <name> --trusted-root <json> [--yes]
  promptsign-reference trust add <name> <url|file> [--signer <glob>] [--yes]
  promptsign-reference trust list | trust rm <name>

Signing unit is a bundle manifest: for a directory, every file in it (skills
include the scripts they run); for a single file, a sidecar <file>.psig.json.
Verification = signature + integrity against disk + trust policy + TOFU pins.

This is the reference implementation. It signs with a local key (spec 01-04)
and verifies local-key and keyless (Sigstore) signatures, offline, against the
built-in public root, named roots and trust bundles (spec 05, 07). Keyless
signing, the revocation feed, embedded signatures and OpenSSF Model Signing
verification live in the promptsign CLI.`;

function fail(msg) {
  process.stderr.write(`promptsign-reference: ${msg}\n`);
  process.exit(1);
}

const ICONS = { pass: '[ OK ]', warn: '[WARN]', fail: '[FAIL]', unsigned: '[----]' };

// Runtime bookkeeping a harness writes into an artifact directory after it
// installed it. Naming it is explanation only: the finding stands.
function harnessNote(relPath) {
  if (relPath.split('/')[0] === '.in_use' || relPath === '.orphaned_at') {
    return 'Claude Code plugin bookkeeping, written into this directory after install.';
  }
  return null;
}

function printResult(r, { quiet = false } = {}) {
  if (quiet && r.action === 'pass') return;
  const icon = r.signed ? ICONS[r.action] : ICONS.unsigned;
  let who = ' (unsigned)';
  if (r.identity) who = ` signed by ${r.identity}${r.issuer ? ` via ${r.issuer}` : ''}`;
  else if (r.signed) who = ' (signature did not verify)';
  const tags = [];
  if (r.format === 'oms') tags.push('OMS');
  if (r.root && r.root !== DEFAULT_ROOT) tags.push(`root ${r.root}`);
  const tagText = tags.length ? ` (${tags.join(', ')})` : '';
  process.stdout.write(
    `${icon} ${r.name}${r.version ? '@' + r.version : ''}${who}${tagText} — ${r.target}\n`,
  );
  const unlisted = 'unlisted file present: ';
  for (const f of r.findings) {
    process.stdout.write(`       ${f.level.toUpperCase()}: ${f.message}\n`);
    const note = f.message.startsWith(unlisted) && harnessNote(f.message.slice(unlisted.length));
    if (note) process.stdout.write(`              note: ${note}\n`);
  }
}

function exitFor(results) {
  process.exit(results.some((r) => r.action === 'fail') ? 2 : 0);
}

function cmdKeygen(args) {
  const { values } = parseArgs({
    args,
    options: { identity: { type: 'string' }, force: { type: 'boolean' }, dir: { type: 'string' } },
  });
  const res = keygen({ identity: values.identity, force: values.force, dir: values.dir });
  process.stdout.write(`generated ed25519 key: ${res.keyPath}\nkeyid: ${res.keyid}\n`);
  if (values.identity) process.stdout.write(`identity: ${values.identity}\n`);
  else
    process.stdout.write(
      `identity defaults to key:${res.keyid.slice(0, 16)} (set one with --identity)\n`,
    );
}

function cmdSign(args) {
  const { values, positionals } = parseArgs({
    args,
    allowPositionals: true,
    options: {
      name: { type: 'string' },
      version: { type: 'string' },
      kind: { type: 'string' },
      identity: { type: 'string' },
      key: { type: 'string' },
    },
  });
  const target = positionals[0];
  if (!target) fail('sign: missing <dir|file>');
  if (!fs.existsSync(target)) fail(`sign: no such path: ${target}`);
  const st = fs.statSync(target);
  const privateKey = loadPrivateKey(values.key || defaultKeyPath());
  const identity = values.identity || defaultIdentity(crypto.createPublicKey(privateKey));
  const abs = path.resolve(target);
  const manifest = buildManifest({
    root: st.isDirectory() ? abs : path.dirname(abs),
    singleFile: st.isDirectory() ? null : abs,
    name: values.name,
    version: values.version,
    kind: values.kind,
  });
  const bundle = signManifest(manifest, privateKey, identity);
  const out = writeBundle(abs, bundle);
  // Self-check: verify the freshly written bundle end-to-end (catches
  // canonicalization drift immediately, at the signer, not at consumers).
  const check = verifyTarget(abs, { updatePins: false, skipPolicy: true });
  if (check.action === 'fail') {
    fs.rmSync(out);
    fail(
      `self-verification of freshly signed bundle failed:\n  ${check.findings.map((f) => f.message).join('\n  ')}`,
    );
  }
  process.stdout.write(
    `signed ${manifest.kind} "${manifest.name}" (${manifest.files.length} file${manifest.files.length === 1 ? '' : 's'}) as ${identity}\nbundle: ${out}\n`,
  );
}

function cmdVerify(args) {
  const { values, positionals } = parseArgs({
    args,
    allowPositionals: true,
    options: {
      policy: { type: 'string' },
      json: { type: 'boolean' },
      'no-pin-updates': { type: 'boolean' },
    },
  });
  const target = positionals[0];
  if (!target) fail('verify: missing <dir|file>');
  if (!fs.existsSync(target)) fail(`verify: no such path: ${target}`);
  const r = verifyTarget(target, {
    policyPath: values.policy,
    updatePins: !values['no-pin-updates'],
  });
  if (values.json) process.stdout.write(JSON.stringify(r, null, 2) + '\n');
  else printResult(r);
  exitFor([r]);
}

function cmdVerifyTree(args) {
  const { values, positionals } = parseArgs({
    args,
    allowPositionals: true,
    options: {
      policy: { type: 'string' },
      json: { type: 'boolean' },
      quiet: { type: 'boolean' },
      'no-pin-updates': { type: 'boolean' },
    },
  });
  if (positionals.length === 0) fail('verify-tree: missing <root>...');
  const results = verifyTree(positionals, {
    policyPath: values.policy,
    updatePins: !values['no-pin-updates'],
  });
  if (values.json) {
    process.stdout.write(JSON.stringify(results, null, 2) + '\n');
  } else {
    for (const r of results) printResult(r, { quiet: values.quiet });
    const counts = { pass: 0, warn: 0, fail: 0 };
    for (const r of results) counts[r.action]++;
    process.stdout.write(
      `\n${results.length} artifact(s): ${counts.pass} ok, ${counts.warn} warning, ${counts.fail} failed\n`,
    );
  }
  exitFor(results);
}

function cmdPolicy(args) {
  const sub = args[0];
  if (sub === 'init') {
    const { values } = parseArgs({ args: args.slice(1), options: { global: { type: 'boolean' } } });
    const dir = values.global ? promptsignHome() : path.join(process.cwd(), '.promptsign');
    const p = path.join(dir, 'policy.json');
    if (fs.existsSync(p)) fail(`policy already exists: ${p}`);
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(p, JSON.stringify(DEFAULT_POLICY, null, 2) + '\n');
    process.stdout.write(`wrote ${p}\n`);
  } else if (sub === 'show') {
    const { policy, source } = loadPolicy();
    process.stdout.write(`# source: ${source}\n${JSON.stringify(policy, null, 2)}\n`);
  } else {
    fail('policy: expected "init" or "show"');
  }
}

function cmdPin(args) {
  const sub = args[0];
  const pins = loadPins();
  if (sub === 'list' || sub === undefined) {
    const names = Object.keys(pins).sort();
    if (names.length === 0) process.stdout.write('no pins recorded\n');
    for (const n of names) {
      process.stdout.write(
        `${n} -> ${pins[n].identity} (key ${pins[n].keyid.slice(0, 16)}…, since ${pins[n].first_seen})\n`,
      );
    }
  } else if (sub === 'rm') {
    const name = args[1];
    if (!name) fail('pin rm: missing <name>');
    if (!pins[name]) fail(`no pin for "${name}"`);
    delete pins[name];
    savePins(pins);
    process.stdout.write(`removed pin for "${name}"\n`);
  } else {
    fail('pin: expected "list" or "rm <name>"');
  }
}

async function cmdTrust(args) {
  const sub = args[0];
  if (sub === 'fetch') {
    const { values, positionals } = parseArgs({
      args: args.slice(1),
      allowPositionals: true,
      options: { force: { type: 'boolean' } },
    });
    // A name refreshes that bundle alone. No name refreshes the built-in
    // root, then every installed bundle (spec/07 §2.2).
    if (positionals[0] !== undefined) return trust.fetchBundles(positionals[0]);
    await trust.fetchPublicRoot(Boolean(values.force));
    return trust.fetchBundles(null);
  }
  if (sub === 'show') return trust.show();
  if (sub === 'list') return trust.list();
  if (sub === 'rm') {
    if (!args[1]) fail('trust rm: missing <name>');
    return trust.remove(args[1]);
  }
  if (sub === 'add') {
    const { values, positionals } = parseArgs({
      args: args.slice(1),
      allowPositionals: true,
      options: {
        ca: { type: 'string' },
        'trusted-root': { type: 'string' },
        signer: { type: 'string' },
        yes: { type: 'boolean' },
      },
    });
    const name = positionals[0];
    if (!name) fail('trust add: missing <name>');
    if (positionals[1] !== undefined) {
      if (values.ca !== undefined || values['trusted-root'] !== undefined) {
        fail('trust add: give a bundle <url|file>, or --ca / --trusted-root, not both');
      }
      return trust.addBundle(name, positionals[1], values.signer, Boolean(values.yes));
    }
    return trust.addRoot(name, {
      ca: values.ca,
      trustedRoot: values['trusted-root'],
      yes: Boolean(values.yes),
    });
  }
  fail('trust: expected "fetch", "show", "add", "list" or "rm"');
}

const [cmd, ...rest] = process.argv.slice(2);
try {
  switch (cmd) {
    case 'keygen':
      cmdKeygen(rest);
      break;
    case 'sign':
      cmdSign(rest);
      break;
    case 'verify':
      cmdVerify(rest);
      break;
    case 'verify-tree':
      cmdVerifyTree(rest);
      break;
    case 'policy':
      cmdPolicy(rest);
      break;
    case 'pin':
      cmdPin(rest);
      break;
    case 'trust':
      await cmdTrust(rest);
      break;
    case 'version':
    case '--version':
    case '-v':
      process.stdout.write(VERSION + '\n');
      break;
    case 'help':
    case '--help':
    case '-h':
    case undefined:
      process.stdout.write(USAGE + '\n');
      break;
    default:
      fail(`unknown command "${cmd}" (try: promptsign-reference help)`);
  }
} catch (e) {
  fail(e.message);
}
