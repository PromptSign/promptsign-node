// The decision log (spec/08): the managed policy or the user's turns it on,
// --decision-log names a file for one command, a project policy cannot turn
// it on, and the log rotates at its limit. PROMPTSIGN_MANAGED_DIR stands in
// for the platform directory, so these tests skip on a machine that has one.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { platformDir } from '../src/managed.mjs';

const CLI = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'src', 'index.mjs');
const skip = fs.existsSync(platformDir())
  ? `${platformDir()} exists, so PROMPTSIGN_MANAGED_DIR does not apply`
  : false;

const policy = (extra) =>
  JSON.stringify({ schema: 'promptsign/policy/v1', default: 'warn', rules: [], ...extra });

function setup() {
  // Real path: macOS links /var to /private/var, and the CLI's cwd resolves it.
  const base = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'psign-dlog-')));
  const dirs = {
    base,
    home: path.join(base, 'ps'),
    managed: path.join(base, 'managed'),
    project: path.join(base, 'project'),
  };
  for (const d of Object.values(dirs)) fs.mkdirSync(d, { recursive: true });
  fs.writeFileSync(path.join(dirs.project, 'CLAUDE.md'), '# rules\n');
  dirs.run = (...args) => {
    const env = {
      ...process.env,
      PROMPTSIGN_HOME: dirs.home,
      PROMPTSIGN_MANAGED_DIR: dirs.managed,
      USER: 'tester',
      USERNAME: 'tester',
      NO_COLOR: '1',
    };
    delete env.PROMPTSIGN_TRUST_DIR;
    delete env.PROMPTSIGN_POLICY;
    const r = spawnSync(process.execPath, [CLI, ...args], {
      cwd: dirs.project,
      env,
      encoding: 'utf8',
    });
    return { code: r.status, out: r.stdout + r.stderr, stdout: r.stdout };
  };
  return dirs;
}

const records = (file) =>
  fs.existsSync(file)
    ? fs
        .readFileSync(file, 'utf8')
        .split('\n')
        .filter(Boolean)
        .map((l) => JSON.parse(l))
    : [];

test('a managed policy logs every verification', { skip }, () => {
  const d = setup();
  fs.writeFileSync(path.join(d.managed, 'managed-policy.json'), policy({ decision_log: true }));
  const r = d.run('verify', 'CLAUDE.md', '--no-pin-updates');
  assert.equal(r.code, 0, r.out);

  const [rec, ...rest] = records(path.join(d.managed, 'log', 'decisions-tester.jsonl'));
  assert.equal(rest.length, 0);
  assert.deepEqual(Object.keys(rec), [
    'schema',
    'time',
    'verifier',
    'user',
    'event',
    'target',
    'name',
    'signed',
    'result',
    'rule',
    'revocation',
    'policy_source',
    'findings',
  ]);
  assert.equal(rec.schema, 'promptsign/decision-log/v1');
  assert.match(rec.verifier, /^promptsign-reference\//);
  assert.equal(rec.event, 'verify');
  assert.equal(rec.target, path.join(d.project, 'CLAUDE.md'));
  assert.equal(rec.result, 'warn');
  assert.deepEqual(rec.rule, { layer: 'managed', pattern: '*', action: 'warn' });
  assert.equal(rec.revocation, 'unchecked');
});

test('a project policy cannot turn the log on', { skip }, () => {
  const d = setup();
  fs.mkdirSync(path.join(d.project, '.promptsign'));
  fs.writeFileSync(
    path.join(d.project, '.promptsign', 'policy.json'),
    policy({ decision_log: true }),
  );
  d.run('verify', 'CLAUDE.md', '--no-pin-updates');
  assert.ok(!fs.existsSync(path.join(d.home, 'log')));
  assert.ok(!fs.existsSync(path.join(d.managed, 'log')));
});

test('the flag logs one command, and the JSON output carries no evidence', { skip }, () => {
  const d = setup();
  const file = path.join(d.base, 'verify.jsonl');
  const r = d.run('verify-tree', d.project, '--json', '--decision-log', file);
  assert.equal(r.code, 0, r.out);
  assert.ok(!r.stdout.includes('evidence'));

  const [rec] = records(file);
  assert.equal(rec.event, 'verify-tree');
  assert.equal(rec.name, 'CLAUDE');
  assert.equal(rec.rule.layer, 'user');
});

test('the log rotates at decision_log_max_bytes and keeps four copies', { skip }, () => {
  const d = setup();
  fs.writeFileSync(
    path.join(d.home, 'policy.json'),
    policy({ decision_log: true, decision_log_dir: 'logs', decision_log_max_bytes: 1 }),
  );
  for (let i = 0; i < 7; i++) d.run('verify', 'CLAUDE.md', '--no-pin-updates');
  const log = path.join(d.home, 'logs', 'decisions-tester.jsonl');
  for (let i = 1; i <= 4; i++) assert.ok(fs.existsSync(`${log}.${i}`), `copy ${i}`);
  assert.ok(!fs.existsSync(`${log}.5`));
  assert.equal(records(log).length, 1);
});
