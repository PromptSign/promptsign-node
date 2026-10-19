// Approvals (spec/09): the verdicts of test/fixtures/approvals/README.md, a
// byte-identical copy of spec/test/fixtures/approvals, then approval rules
// end to end through the CLI with a fresh PROMPTSIGN_HOME.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { listingFor, verifyApproval } from '../src/approval.mjs';
import { evaluate } from '../src/policy.mjs';
import { rootFromTrustedRoot } from '../src/trustroot.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const CLI = path.join(HERE, '..', 'src', 'index.mjs');
const F = path.join(HERE, 'fixtures', 'approvals');
const ROOT = path.join(HERE, 'fixtures', 'rekor-v2', 'trusted_root.json');
const DIGEST = '38209d34368a5cc6ade9034887f7fa314647e657153dfdee0b13f543c410fa9a';
const SIGNED_AT = Date.UTC(2026, 9, 1, 12) / 1000;

const fixture = (n) => JSON.parse(fs.readFileSync(path.join(F, n), 'utf8'));
const acme = () => [rootFromTrustedRoot('acme-v2', JSON.parse(fs.readFileSync(ROOT, 'utf8')))];

// The skill conformance.sh builds with mkskill.
function mkskill() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'psign-appr-'));
  fs.mkdirSync(path.join(dir, 'scripts'));
  fs.mkdirSync(path.join(dir, 'references'));
  fs.writeFileSync(path.join(dir, 'SKILL.md'), '# demo-skill\r\nDoes things.  \r\n');
  fs.writeFileSync(path.join(dir, 'scripts', 'run.py'), 'print("hello")\n');
  fs.writeFileSync(path.join(dir, 'references', 'rules.md'), 'rules here\n');
  return dir;
}

function run(h, ...args) {
  const env = { ...process.env, PROMPTSIGN_HOME: h, NO_COLOR: '1' };
  delete env.PROMPTSIGN_TRUST_DIR;
  delete env.PROMPTSIGN_POLICY;
  const r = spawnSync(process.execPath, [CLI, ...args], { env, encoding: 'utf8' });
  return { code: r.status, stdout: r.stdout, stderr: r.stderr };
}

test('the content listing matches the fixture', () => {
  const l = listingFor(mkskill());
  assert.equal(l.text, fs.readFileSync(path.join(F, 'listing.txt'), 'utf8'));
  assert.equal(l.digest, DIGEST);
});

test('both carriages verify, and an approval of other content does not cover the skill', () => {
  const bob = verifyApproval(fixture('bob.json'), DIGEST, acme());
  assert.deepEqual(
    [bob.identity, bob.issuer, bob.root, bob.signedAt],
    ['bob@acme.test', 'https://sso.acme.test', 'acme-v2', SIGNED_AT],
  );
  const carol = verifyApproval(fixture('carol.sigstore.json'), DIGEST, acme());
  assert.deepEqual([carol.identity, carol.root], ['carol@acme.test', 'acme-v2']);
  assert.equal(verifyApproval(fixture('other-content.json'), DIGEST, acme()), null);
});

test('an approval fails under a root it does not chain to, or with its statement changed', () => {
  assert.throws(() => verifyApproval(fixture('bob.json'), DIGEST, []));
  const forged = fixture('bob.json');
  const doc = JSON.parse(Buffer.from(forged.envelope.payload, 'base64').toString('utf8'));
  doc.subject[0].digest.sha256 = '1'.repeat(64);
  forged.envelope.payload = Buffer.from(JSON.stringify(doc)).toString('base64');
  assert.throws(() => verifyApproval(forged, '1'.repeat(64), acme()));
});

const approvalRule = (extra = {}) => ({
  schema: 'promptsign/policy/v1',
  rules: [
    {
      pattern: '*',
      action: 'enforce',
      approval: { approvers: [{ identity: '*@acme.test' }], threshold: 2 },
      ...extra,
    },
  ],
});
const approved = (...who) =>
  who.map((identity) => ({ identity, issuer: 'https://sso.acme.test', root: 'acme-v2' }));

test('approvals stand in for a signature unless the rule constrains the author', () => {
  const unsigned = (policy, approvals) =>
    evaluate(policy, { name: 's', signed: false, approvals }, {});

  assert.equal(
    unsigned(approvalRule(), approved('bob@acme.test', 'carol@acme.test')).action,
    'pass',
  );
  // The same approver twice counts once.
  const once = unsigned(approvalRule(), approved('bob@acme.test', 'bob@acme.test'));
  assert.equal(once.action, 'fail');
  assert.match(once.findings[0].message, /has 1 of 2 required approvals/);
  // A rule that names the author still wants a signature.
  const named = unsigned(
    approvalRule({ identity: '*@acme.test' }),
    approved('bob@acme.test', 'carol@acme.test'),
  );
  assert.equal(named.action, 'fail');
  assert.match(named.findings[0].message, /unsigned artifact/);
});

test('the CLI counts the fixture approvals beside a skill', () => {
  const h = fs.mkdtempSync(path.join(os.tmpdir(), 'psign-appr-home-'));
  const skill = mkskill();
  const policy = path.join(h, 'policy.json');
  const approvals = path.join(skill, '.promptsign', 'approvals');

  fs.writeFileSync(policy, JSON.stringify(approvalRule()));
  // A home with no roots and no approvals refuses the artifact; it is no error.
  assert.equal(run(h, 'verify', skill, '--policy', policy, '--no-pin-updates').code, 2);
  assert.equal(run(h, 'trust', 'add', 'acme-v2', '--trusted-root', ROOT, '--yes').code, 0);

  fs.mkdirSync(approvals, { recursive: true });
  fs.copyFileSync(path.join(F, 'bob.json'), path.join(approvals, 'bob.json'));
  fs.copyFileSync(path.join(F, 'other-content.json'), path.join(approvals, 'other.json'));
  let r = run(h, 'verify', skill, '--policy', policy, '--json', '--no-pin-updates');
  assert.equal(r.code, 2, r.stdout + r.stderr);
  assert.match(r.stdout, /has 1 of 2 required approvals/);

  fs.copyFileSync(path.join(F, 'carol.sigstore.json'), path.join(approvals, 'carol.json'));
  r = run(h, 'verify', skill, '--policy', policy, '--json', '--no-pin-updates');
  assert.equal(r.code, 0, r.stdout + r.stderr);
  const out = JSON.parse(r.stdout);
  assert.deepEqual(
    out.approvals.map((a) => a.identity),
    ['bob@acme.test', 'carol@acme.test'],
  );
  assert.equal(out.signed, false);

  // A policy that names a revocation feed this verifier does not read
  // counts no approvals.
  fs.writeFileSync(
    policy,
    JSON.stringify({ ...approvalRule(), revocation_feed: 'https://acme.test/revocation.json' }),
  );
  r = run(h, 'verify', skill, '--policy', policy, '--json', '--no-pin-updates');
  assert.equal(r.code, 2);
  assert.match(r.stdout, /names a revocation feed/);
});
