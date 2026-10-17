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
import { DEFAULT_POLICY, loadPins, policyLayers, savePins } from './policy.mjs';
import * as decisionLog from './decisionlog.mjs';
import { verifyTarget } from './verify.mjs';
import { verifyTree } from './verifytree.mjs';
import { DEFAULT_ROOT, sortKeys } from './trustroot.mjs';
import * as trust from './trustcmd.mjs';
import crypto from 'node:crypto';

const VERSION = '0.1.0';

const USAGE = `promptsign-reference ${VERSION} — PKI signing for AI instruction files

Usage:
  promptsign-reference keygen [--identity <id>] [--force]
  promptsign-reference sign <dir|file> [--name n] [--version v] [--kind k] [--identity id] [--key path]
  promptsign-reference verify <dir|file> [--policy path] [--json] [--no-pin-updates] [--decision-log file]
  promptsign-reference verify-tree <root>... [--policy path] [--json] [--quiet] [--decision-log file]
  promptsign-reference policy init [--global] | policy show
  promptsign-reference pin list | pin rm <name>
  promptsign-reference trust fetch [--force] [--managed] [<bundle>] | trust show
  promptsign-reference trust add <name> --ca <pem> | trust add <name> --trusted-root <json> [--yes] [--managed]
  promptsign-reference trust add <name> <url|file> [--signer <glob>] [--yes] [--managed]
  promptsign-reference trust list | trust rm <name> [--managed]
  promptsign-reference approve --listing <dir|file>

Signing unit is a bundle manifest: for a directory, every file in it (skills
include the scripts they run); for a single file, a sidecar <file>.psig.json.
Verification = signature + integrity against disk + trust policy + TOFU pins.

This is the reference implementation. It signs with a local key (spec 01-04)
and verifies local-key and keyless (Sigstore) signatures, offline, against the
built-in public root, named roots and trust bundles (spec 05, 07). Keyless
signing, the revocation feed, embedded signatures, OpenSSF Model Signing
verification and approvals live in the promptsign CLI; approve --listing
prints the content listing an approval covers (spec 09), and a policy rule
that requires approvals fails here.`;

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

// The content listing an approval covers (spec/09 §1): the manifest a signer
// would build, one "<sha256>  <path>" line per file, sorted by path bytes.
function cmdApprove(args) {
  const { values, positionals } = parseArgs({
    args,
    allowPositionals: true,
    options: { listing: { type: 'boolean' } },
  });
  if (!values.listing) fail('approve: only --listing here; sign approvals with the promptsign CLI');
  if (!positionals[0]) fail('approve: missing <dir|file>');

  const abs = path.resolve(positionals[0]);
  const manifest = fs.statSync(abs).isDirectory()
    ? buildManifest({ root: abs })
    : buildManifest({ root: path.dirname(abs), singleFile: abs });
  const lines = manifest.files
    .map((f) => [f.path, f.sha256])
    .sort(([a], [b]) => Buffer.compare(Buffer.from(a), Buffer.from(b)));

  process.stdout.write(lines.map(([p, h]) => `${h}  ${p}\n`).join(''));
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

// Appends records to the decision logs the policies turn on and to `file`
// (spec/08). A failed write prints a warning and changes nothing else.
function logDecisions(policyPath, file, records) {
  for (const e of decisionLog.append(decisionLog.sinks(policyPath, file), records)) {
    process.stderr.write(`promptsign-reference: ${e}\n`);
  }
}

function logContext(event) {
  return { verifier: `promptsign-reference/${VERSION}`, event };
}

// Runs a verification; when it throws, logs the error and rethrows.
function logged(values, event, target, run) {
  try {
    return run();
  } catch (e) {
    const ctx = logContext(event);
    logDecisions(values.policy, values['decision-log'], [
      decisionLog.errorRecord(ctx, target ?? '', target, e.message),
    ]);
    throw e;
  }
}

function cmdVerify(args) {
  const { values, positionals } = parseArgs({
    args,
    allowPositionals: true,
    options: {
      policy: { type: 'string' },
      json: { type: 'boolean' },
      'no-pin-updates': { type: 'boolean' },
      'decision-log': { type: 'string' },
    },
  });
  const target = positionals[0];
  if (!target) fail('verify: missing <dir|file>');
  if (!fs.existsSync(target)) fail(`verify: no such path: ${target}`);
  const r = logged(values, 'verify', target, () =>
    verifyTarget(target, {
      policyPath: values.policy,
      updatePins: !values['no-pin-updates'],
    }),
  );
  logDecisions(values.policy, values['decision-log'], [
    decisionLog.verifiedRecord(logContext('verify'), r),
  ]);
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
      'decision-log': { type: 'string' },
    },
  });
  if (positionals.length === 0) fail('verify-tree: missing <root>...');
  const results = logged(values, 'verify-tree', null, () =>
    verifyTree(positionals, {
      policyPath: values.policy,
      updatePins: !values['no-pin-updates'],
    }),
  );
  const ctx = logContext('verify-tree');
  logDecisions(
    values.policy,
    values['decision-log'],
    results.map((r) => decisionLog.verifiedRecord(ctx, r)),
  );
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
    process.stdout.write(policyShow(process.cwd()));
  } else {
    fail('policy: expected "init" or "show"');
  }
}

// `policy show`: every layer with the file it came from (spec/04), then the
// settings in effect. Matches the Rust CLI line for line.
function policyShow(cwd) {
  const layers = policyLayers(undefined, cwd);
  const managed = layers.find((l) => l.layer === 'managed');
  let out = '';
  for (const l of layers) {
    let header = `# project policy (tighten only): ${l.source}`;
    if (l.layer === 'managed') header = `# managed policy: ${l.source}`;
    else if (l.layer === 'user' && managed) header = `# user policy (tighten only): ${l.source}`;
    else if (l.layer === 'user') header = `# source: ${l.source}`;
    // Keys sorted, as the Rust CLI prints them.
    out += `${header}\n${JSON.stringify(sortKeys(l.policy), null, 2)}\n`;
  }
  const set = (layer, key) => layers.some((l) => l.layer === layer && l.policy[key] === true);
  let strict = 'off';
  if (process.env.PROMPTSIGN_STRICT === '1') strict = 'on (PROMPTSIGN_STRICT=1)';
  else if (set('managed', 'strict')) strict = 'on (managed policy)';
  else if (set('user', 'strict')) strict = 'on (user policy)';
  if (managed) {
    if (!layers.some((l) => l.layer === 'user')) {
      out += '# user policy: none (the built-in default does not apply under a managed policy)\n';
    }
    out += `# lock_env: ${
      managed.policy.lock_env === true
        ? 'on (PROMPTSIGN_POLICY, PROMPTSIGN_HOME, PROMPTSIGN_TRUST_DIR and PROMPTSIGN_REVOCATION_FILE are ignored)'
        : 'off'
    }\n`;
    out += `# user_roots: ${
      managed.policy.user_roots === false
        ? 'off (only managed roots and the built-in root are trusted)'
        : 'on'
    }\n`;
  }
  return out + `# strict: ${strict}\n`;
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
      options: { force: { type: 'boolean' }, managed: { type: 'boolean' } },
    });
    const managed = Boolean(values.managed);
    // A name refreshes that bundle alone. No name refreshes the built-in
    // root, then every installed bundle (spec/07 §2.2).
    if (positionals[0] !== undefined) return trust.fetchBundles(positionals[0], managed);
    await trust.fetchPublicRoot(Boolean(values.force), managed);
    return trust.fetchBundles(null, managed);
  }
  if (sub === 'show') return trust.show();
  if (sub === 'list') return trust.list();
  if (sub === 'rm') {
    const { values, positionals } = parseArgs({
      args: args.slice(1),
      allowPositionals: true,
      options: { managed: { type: 'boolean' } },
    });
    if (!positionals[0]) fail('trust rm: missing <name>');
    return trust.remove(positionals[0], Boolean(values.managed));
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
        managed: { type: 'boolean' },
      },
    });
    const name = positionals[0];
    if (!name) fail('trust add: missing <name>');
    if (positionals[1] !== undefined) {
      if (values.ca !== undefined || values['trusted-root'] !== undefined) {
        fail('trust add: give a bundle <url|file>, or --ca / --trusted-root, not both');
      }
      return trust.addBundle(
        name,
        positionals[1],
        values.signer,
        Boolean(values.yes),
        Boolean(values.managed),
      );
    }
    return trust.addRoot(name, {
      ca: values.ca,
      trustedRoot: values['trusted-root'],
      yes: Boolean(values.yes),
      managed: Boolean(values.managed),
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
    case 'approve':
      cmdApprove(rest);
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
  // exitCode rather than process.exit: exiting while fetch is still closing a
  // socket trips an assertion inside libuv on Windows.
  process.stderr.write(`promptsign-reference: ${e.message}
`);
  process.exitCode = 1;
}
