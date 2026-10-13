// The verdicts of test/fixtures/rekor-v2/README.md (spec/07 §6): Rekor v2
// entries proved by a signed checkpoint and dated by RFC 3161 timestamps,
// checked through the CLI with a fresh PROMPTSIGN_HOME. The fixture tree is a
// byte-identical copy of spec/test/fixtures/rekor-v2.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { leafHash, verifyInclusion } from '../src/logproof.mjs';
import { parseGeneralizedTime } from '../src/tsa.mjs';
import { rootFromTrustedRoot, rootToTrustedRoot } from '../src/trustroot.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const CLI = path.join(HERE, '..', 'src', 'index.mjs');
const F = path.join(HERE, 'fixtures', 'rekor-v2');
const SIGNED_AT = Date.UTC(2026, 9, 1, 12) / 1000;

function run(h, ...args) {
  const env = { ...process.env, PROMPTSIGN_HOME: h, NO_COLOR: '1' };
  delete env.PROMPTSIGN_TRUST_DIR;
  delete env.PROMPTSIGN_POLICY;
  const r = spawnSync(process.execPath, [CLI, ...args], { env, encoding: 'utf8' });
  return { code: r.status, stdout: r.stdout, stderr: r.stderr };
}

function installed() {
  const h = fs.mkdtempSync(path.join(os.tmpdir(), 'psign-rekor2-'));
  const r = run(
    h,
    'trust',
    'add',
    'acme-v2',
    '--trusted-root',
    path.join(F, 'trusted_root.json'),
    '--yes',
  );
  assert.equal(r.code, 0, r.stdout + r.stderr);
  return h;
}

function verify(h, name) {
  const r = run(h, 'verify', path.join(F, 'artifacts', name), '--json', '--no-pin-updates');
  return { code: r.code, result: JSON.parse(r.stdout) };
}

test('the root keeps its Rekor v2 log and timestamp authority', () => {
  const doc = JSON.parse(fs.readFileSync(path.join(F, 'trusted_root.json'), 'utf8'));
  const root = rootFromTrustedRoot('acme-v2', doc);
  assert.deepEqual(
    root.rekorLogs.map((l) => l.keyType),
    ['p256', 'ed25519'],
  );
  assert.equal(root.rekorLogs[1].origin(), 'rekor-eb2cf13b.test');
  assert.equal(root.tsas.length, 1);
  const again = rootFromTrustedRoot('acme-v2', rootToTrustedRoot(root));
  assert.deepEqual(
    again.rekorLogs.map((l) => l.logId),
    root.rekorLogs.map((l) => l.logId),
  );
  assert.equal(again.tsas[0].certs.length, 2);
});

test('without the root every artifact fails', () => {
  const h = fs.mkdtempSync(path.join(os.tmpdir(), 'psign-rekor2-'));
  assert.equal(verify(h, 'signed.txt').code, 2);
});

test('Rekor v2 artifacts reach the README verdicts', () => {
  const h = installed();
  const expect = {
    'signed.txt': null,
    'checkpoint-witness-first.txt': null,
    'v1-with-timestamp.txt': null,
    'no-timestamp.txt': /no verified signing time/,
    'timestamp-other-signature.txt': /timestamp does not cover this signature/,
    'timestamp-after-certificate.txt': /outside certificate validity/,
    'checkpoint-other-key.txt': /checkpoint carries no signature from log/,
    'proof-tampered.txt': /inclusion proof does not lead to the checkpoint's root hash/,
  };
  for (const [name, failure] of Object.entries(expect)) {
    const { code, result } = verify(h, name);
    if (failure === null) {
      assert.equal(code, 0, `${name}: ${JSON.stringify(result.findings)}`);
      assert.equal(result.root, 'acme-v2');
      assert.equal(result.integratedTime, SIGNED_AT, name);
    } else {
      assert.equal(code, 2, name);
      assert.match(result.findings[0].message, failure, name);
    }
  }
});

test('genTime drops fractions and refuses offsets', () => {
  assert.equal(parseGeneralizedTime(Buffer.from('19700101000000Z')), 0);
  assert.equal(
    parseGeneralizedTime(Buffer.from('20250612120220.123Z')),
    parseGeneralizedTime(Buffer.from('20250612120220Z')),
  );
  assert.throws(
    () => parseGeneralizedTime(Buffer.from('20250612120220+0100')),
    /unsupported genTime/,
  );
});

test('an inclusion proof is checked against the tree size and root', () => {
  // A two-leaf tree: the proof for leaf 0 is leaf 1's hash.
  const [a, b] = [leafHash(Buffer.from('a')), leafHash(Buffer.from('b'))];
  const rootHash = crypto
    .createHash('sha256')
    .update(Buffer.concat([Buffer.from([1]), a, b]))
    .digest();
  verifyInclusion(0n, 2n, a, [b], rootHash);
  assert.throws(() => verifyInclusion(0n, 2n, b, [a], rootHash), /does not lead/);
  assert.throws(() => verifyInclusion(2n, 2n, a, [b], rootHash), /outside a tree/);
  assert.throws(() => verifyInclusion(0n, 2n, a, [], rootHash), /too few hashes/);
});
