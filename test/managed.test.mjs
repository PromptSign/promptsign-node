// The managed layer (spec/04 "Managed policy", spec/07 §2.4): a managed
// policy the user's and the project's cannot loosen, managed roots and
// bundles every user trusts, user_roots and lock_env. PROMPTSIGN_MANAGED_DIR
// stands in for the platform directory, so these tests skip on a machine
// that has one.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { platformDir } from '../src/managed.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const CLI = path.join(HERE, '..', 'src', 'index.mjs');
const F = path.join(HERE, 'fixtures', 'trust-roots');
const art = (n) => path.join(F, 'artifacts', `${n}.txt`);
const bundle = (n) => path.join(F, 'bundles', n, 'trust-bundle.json');
const skip = fs.existsSync(platformDir())
  ? `${platformDir()} exists, so PROMPTSIGN_MANAGED_DIR does not apply`
  : false;

const policy = (extra) =>
  JSON.stringify({ schema: 'promptsign/policy/v1', default: 'warn', rules: [], ...extra });

// A user home with the pinned public root, an empty managed directory, and a
// project directory to run in.
function setup() {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'psign-managed-'));
  const dirs = {
    base,
    home: path.join(base, 'ps'),
    osHome: path.join(base, 'os-home'),
    managed: path.join(base, 'managed'),
    project: path.join(base, 'project'),
  };
  for (const d of Object.values(dirs)) fs.mkdirSync(d, { recursive: true });
  fs.mkdirSync(path.join(dirs.home, 'trust'));
  for (const f of ['fulcio.pem', 'rekor.pub']) {
    fs.copyFileSync(path.join(F, 'public', f), path.join(dirs.home, 'trust', f));
  }
  dirs.run = (...args) => {
    const env = {
      ...process.env,
      PROMPTSIGN_HOME: dirs.home,
      PROMPTSIGN_MANAGED_DIR: dirs.managed,
      HOME: dirs.osHome,
      USERPROFILE: dirs.osHome,
      NO_COLOR: '1',
    };
    delete env.PROMPTSIGN_TRUST_DIR;
    delete env.PROMPTSIGN_POLICY;
    delete env.PROMPTSIGN_STRICT;
    const r = spawnSync(process.execPath, [CLI, ...args], {
      cwd: dirs.project,
      env,
      encoding: 'utf8',
    });
    return { code: r.status, out: r.stdout + r.stderr };
  };
  dirs.managedPolicy = (extra) =>
    fs.writeFileSync(path.join(dirs.managed, 'managed-policy.json'), policy(extra));
  return dirs;
}

test('a managed bundle verifies for every user and its name cannot be taken', { skip }, () => {
  const d = setup();
  const added = d.run('trust', 'add', 'acme', bundle('acme-v1'), '--yes', '--managed');
  assert.equal(added.code, 0, added.out);
  assert.ok(fs.existsSync(path.join(d.managed, 'trust', 'bundles', 'acme', 'trust-bundle.json')));

  const verified = d.run('verify', art('prod-signed'), '--no-pin-updates');
  assert.equal(verified.code, 0, verified.out);
  assert.match(verified.out, /\(root acme\/prod\)/);

  const list = d.run('trust', 'list').out;
  assert.match(list, /^acme\/prod .*\(managed bundle acme v1, expires /m);

  const clash = d.run('trust', 'add', 'acme', bundle('acme-v1'), '--yes');
  assert.equal(clash.code, 1, clash.out);
  assert.match(clash.out, /trust bundle "acme" is managed on this machine/);

  const removed = d.run('trust', 'rm', 'acme', '--managed');
  assert.equal(removed.code, 0, removed.out);
  assert.equal(d.run('verify', art('prod-signed'), '--no-pin-updates').code, 2);
});

test('user_roots: false drops the user bundle', { skip }, () => {
  const d = setup();
  assert.equal(d.run('trust', 'add', 'acme', bundle('acme-v1'), '--yes').code, 0);
  assert.equal(d.run('verify', art('prod-signed'), '--no-pin-updates').code, 0);

  d.managedPolicy({ user_roots: false });
  const r = d.run('verify', art('prod-signed'), '--no-pin-updates');
  assert.equal(r.code, 2, r.out);
  assert.match(d.run('trust', 'list').out, /ignored, the managed policy sets user_roots to false/);
});

test('the user and project policies cannot loosen a managed policy', { skip }, () => {
  const d = setup();
  const unsigned = path.join(d.project, 'CLAUDE.md');
  fs.writeFileSync(unsigned, '# rules\n');
  fs.writeFileSync(path.join(d.home, 'policy.json'), policy({ default: 'off' }));
  assert.equal(d.run('verify', unsigned, '--no-pin-updates').code, 0);

  d.managedPolicy({ default: 'enforce' });
  fs.mkdirSync(path.join(d.project, '.promptsign'));
  fs.writeFileSync(path.join(d.project, '.promptsign', 'policy.json'), policy({ default: 'off' }));
  const r = d.run('verify', unsigned, '--json', '--no-pin-updates');
  assert.equal(r.code, 2, r.out);
  const result = JSON.parse(r.out);
  assert.equal(
    result.policySource,
    `${path.join(d.managed, 'managed-policy.json')} (managed) + ` +
      `${path.join(d.home, 'policy.json')} (tighten only) + ` +
      `${path.join(d.project, '.promptsign', 'policy.json')} (tighten only)`,
  );

  // A user policy over a managed "warn" tightens it, with a prefix.
  d.managedPolicy({});
  fs.writeFileSync(path.join(d.home, 'policy.json'), policy({ default: 'enforce' }));
  const tightened = JSON.parse(d.run('verify', unsigned, '--json', '--no-pin-updates').out);
  assert.equal(tightened.action, 'fail');
  assert.ok(tightened.findings.some((f) => f.message.startsWith('user policy: unsigned')));
});

test('lock_env ignores PROMPTSIGN_HOME and PROMPTSIGN_POLICY', { skip }, () => {
  const d = setup();
  assert.equal(d.run('trust', 'add', 'acme', bundle('acme-v1'), '--yes').code, 0);
  d.managedPolicy({ lock_env: true });

  // The user's bundle lives under PROMPTSIGN_HOME, which no longer applies.
  const r = d.run('verify', art('prod-signed'), '--no-pin-updates');
  assert.equal(r.code, 2, r.out);

  const show = d.run('policy', 'show').out;
  assert.match(show, /^# managed policy: /);
  assert.match(show, /^# user policy: none \(the built-in default does not apply/m);
  assert.match(show, /^# lock_env: on \(PROMPTSIGN_POLICY, PROMPTSIGN_HOME,/m);
  assert.match(show, /# strict: off\n$/);
});
