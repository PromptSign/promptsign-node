// `trust fetch` through a TUF repository over real HTTP, the same cases as the
// Rust CLI's tuf_e2e.rs: the root rotates, the public trusted_root.json and
// signing config land in the trust directory, and the client refuses a
// tampered target, a root its predecessor did not sign, an expired timestamp
// and a rolled-back timestamp.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalJson } from '../src/tuf.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const CLI = path.join(HERE, '..', 'src', 'index.mjs');
const PUBLIC = path.join(HERE, 'fixtures', 'trust-roots', 'public');
const TRUSTED_ROOT = fs.readFileSync(path.join(HERE, 'fixtures', 'rekor-v2', 'trusted_root.json'));
const FAR = '2099-01-01T00:00:00Z';

const SIGNING_CONFIG = Buffer.from(
  JSON.stringify(
    {
      mediaType: 'application/vnd.dev.sigstore.signingconfig.v0.2+json',
      caUrls: [],
      rekorTlogUrls: [],
      tsaUrls: [],
    },
    null,
    2,
  ),
);

function tufKey() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const pub = {
    keytype: 'ecdsa',
    scheme: 'ecdsa-sha2-nistp256',
    keyval: { public: publicKey.export({ type: 'spki', format: 'pem' }) },
  };
  const id = crypto.createHash('sha256').update(canonicalJson(pub)).digest('hex');
  return { privateKey, pub, id };
}

function signMetadata(signed, keys) {
  const message = Buffer.from(canonicalJson(signed));
  const signatures = keys.map((k) => ({
    keyid: k.id,
    sig: crypto.sign('sha256', message, { key: k.privateKey, dsaEncoding: 'der' }).toString('hex'),
  }));
  return Buffer.from(JSON.stringify({ signatures, signed }, null, 1));
}

function root(version, key) {
  const role = { keyids: [key.id], threshold: 1 };
  return {
    _type: 'root',
    spec_version: '1.0',
    version,
    expires: FAR,
    consistent_snapshot: true,
    keys: { [key.id]: key.pub },
    roles: { root: role, targets: role, snapshot: role, timestamp: role },
  };
}

const fileMeta = (bytes) => ({
  length: bytes.length,
  hashes: { sha256: crypto.createHash('sha256').update(bytes).digest('hex') },
});

// Timestamp, snapshot and targets at `version`, signed by `key`, and the
// targets at their consistent-snapshot paths.
function publish(files, key, version, expires, targets) {
  const listed = {};
  for (const [name, bytes] of targets) {
    const meta = fileMeta(bytes);
    files[`/tuf/targets/${meta.hashes.sha256}.${name}`] = bytes;
    listed[name] = meta;
  }
  const meta = (type, extra) => ({ _type: type, spec_version: '1.0', version, expires, ...extra });
  const targetsJson = signMetadata(meta('targets', { targets: listed }), [key]);
  const snapshotJson = signMetadata(meta('snapshot', { meta: { 'targets.json': { version } } }), [
    key,
  ]);
  const timestampJson = signMetadata(
    meta('timestamp', { meta: { 'snapshot.json': { ...fileMeta(snapshotJson), version } } }),
    [key],
  );
  files[`/tuf/${version}.targets.json`] = targetsJson;
  files[`/tuf/${version}.snapshot.json`] = snapshotJson;
  files['/tuf/timestamp.json'] = timestampJson;
}

// A repository whose root rotates from k1 to k2, and a server for it that also
// answers the two Sigstore endpoints `trust fetch` reads the pinned pair from.
async function repo(secondRootSigners) {
  const [k1, k2] = [tufKey(), tufKey()];
  const files = {
    '/api/v1/rootCert': fs.readFileSync(path.join(PUBLIC, 'fulcio.pem')),
    '/api/v1/log/publicKey': fs.readFileSync(path.join(PUBLIC, 'rekor.pub')),
    '/tuf/2.root.json': signMetadata(root(2, k2), secondRootSigners(k1, k2)),
  };
  publish(files, k2, 1, FAR, [
    ['trusted_root.json', TRUSTED_ROOT],
    ['signing_config.v0.2.json', SIGNING_CONFIG],
  ]);
  const server = http.createServer((req, res) => {
    const body = files[req.url];
    res.writeHead(body ? 200 : 404);
    res.end(body ?? 'not found');
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'psign-tuf-'));
  fs.writeFileSync(path.join(work, 'initial-root.json'), signMetadata(root(1, k1), [k1]));
  const url = `http://127.0.0.1:${server.address().port}`;
  const fetchTrust = () =>
    new Promise((resolve) => {
      const env = {
        ...process.env,
        PROMPTSIGN_HOME: path.join(work, 'home'),
        PROMPTSIGN_TRUST_DIR: path.join(work, 'trust'),
        PROMPTSIGN_FULCIO_URL: url,
        PROMPTSIGN_REKOR_URL: url,
        PROMPTSIGN_TUF_URL: `${url}/tuf`,
        PROMPTSIGN_TUF_ROOT: path.join(work, 'initial-root.json'),
      };
      const child = spawn(process.execPath, [CLI, 'trust', 'fetch'], {
        env,
        stdio: ['ignore', 'pipe', 'pipe'],
      });
      let stdout = '';
      let stderr = '';
      child.stdout.on('data', (d) => (stdout += d));
      child.stderr.on('data', (d) => (stderr += d));
      child.on('close', (code) => resolve({ code, stdout, stderr }));
    });
  return { files, k2, work, url, server, fetchTrust, trust: path.join(work, 'trust') };
}

test('canonical JSON sorts keys and escapes only quote and backslash', () => {
  assert.equal(
    canonicalJson({ b: [1, true, null], a: 'x"y\\z\n', _t: { z: 0, y: -2 } }),
    '{"_t":{"y":-2,"z":0},"a":"x\\"y\\\\z\n","b":[1,true,null]}',
  );
  assert.throws(() => canonicalJson({ a: 1.5 }), /non-integer number/);
});

test('trust fetch follows a root rotation and refuses a rollback', async () => {
  const r = await repo((k1, k2) => [k1, k2]);
  try {
    const out = await r.fetchTrust();
    assert.equal(out.code, 0, out.stderr);
    assert.match(out.stdout, /trusted_root\.json/);
    assert.deepEqual(fs.readFileSync(path.join(r.trust, 'trusted_root.json')), TRUSTED_ROOT);
    assert.deepEqual(fs.readFileSync(path.join(r.trust, 'signing_config.json')), SIGNING_CONFIG);
    const cache = path.join(
      r.trust,
      'tuf',
      r.url.replace('http://', '').replace(/[^A-Za-z0-9.-]/g, '_') + '_tuf',
    );
    assert.equal(JSON.parse(fs.readFileSync(path.join(cache, 'root.json'))).signed.version, 2);

    const oldTimestamp = r.files['/tuf/timestamp.json'];
    publish(r.files, r.k2, 2, FAR, [
      ['trusted_root.json', TRUSTED_ROOT],
      ['signing_config.v0.2.json', SIGNING_CONFIG],
    ]);
    assert.equal((await r.fetchTrust()).code, 0);
    r.files['/tuf/timestamp.json'] = oldTimestamp;
    const rolledBack = await r.fetchTrust();
    assert.equal(rolledBack.code, 1);
    assert.match(rolledBack.stderr, /timestamp\.json: version is older than the one already seen/);
  } finally {
    r.server.close();
  }
});

test('a tampered target is refused and nothing is written', async () => {
  const r = await repo((k1, k2) => [k1, k2]);
  try {
    const name = Object.keys(r.files).find((k) => k.endsWith('.trusted_root.json'));
    const bytes = Buffer.from(r.files[name]);
    bytes[bytes.length - 2] ^= 1;
    r.files[name] = bytes;
    const out = await r.fetchTrust();
    assert.equal(out.code, 1);
    assert.match(out.stderr, /trusted_root\.json: sha256 hash does not match/);
    assert.equal(fs.existsSync(path.join(r.trust, 'trusted_root.json')), false);
    assert.equal(fs.existsSync(path.join(r.trust, 'fulcio.pem')), false);
  } finally {
    r.server.close();
  }
});

test('a root its predecessor did not sign is refused', async () => {
  const r = await repo((k1, k2) => [k2]);
  try {
    const out = await r.fetchTrust();
    assert.equal(out.code, 1);
    assert.match(out.stderr, /2\.root\.json: 0 of the 1 required signatures verify/);
  } finally {
    r.server.close();
  }
});

test('an expired timestamp is refused', async () => {
  const r = await repo((k1, k2) => [k1, k2]);
  try {
    publish(r.files, r.k2, 1, '2020-01-01T00:00:00Z', [['trusted_root.json', TRUSTED_ROOT]]);
    const out = await r.fetchTrust();
    assert.equal(out.code, 1);
    assert.match(out.stderr, /timestamp\.json expired at 2020-01-01T00:00:00Z/);
  } finally {
    r.server.close();
  }
});

test('the embedded root is Sigstore root 15, signed by its own threshold', () => {
  const doc = JSON.parse(fs.readFileSync(path.join(HERE, '..', 'src', 'tuf-root.json')));
  assert.equal(doc.signed.version, 15);
  assert.equal(doc.signed.roles.root.threshold, 3);
});
