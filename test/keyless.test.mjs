import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { sha256 } from '../src/canonicalize.mjs';
import { verifyKeylessWith } from '../src/keyless.mjs';
import { rootFromPem, rootFromTrustedRoot } from '../src/trustroot.mjs';
import { formatIso8601 } from '../src/util.mjs';
import { cn, ed25519, ext, keylessBundle, makeCert, p256, trustedRoot } from './x509-build.mjs';

const FIXTURES = path.join(path.dirname(fileURLToPath(import.meta.url)), 'fixtures');
const PUBLIC = path.join(FIXTURES, 'trust-roots', 'public');

function publicRoot() {
  return rootFromPem(
    'sigstore-public',
    fs.readFileSync(path.join(PUBLIC, 'fulcio.pem')),
    fs.readFileSync(path.join(PUBLIC, 'rekor.pub'), 'utf8'),
  );
}

// A real bundle from the public-good Sigstore instance. Its signed file is
// not part of the fixture, so this checks envelope, chain and transparency.
const realBundle = () =>
  JSON.parse(fs.readFileSync(path.join(FIXTURES, 'keyless-bundle.json'), 'utf8'));

test('a public-good keyless bundle verifies offline against the pinned public root', () => {
  const kv = verifyKeylessWith(realBundle(), [publicRoot()]);
  assert.equal(kv.identity, 'info@promptsign.ai');
  assert.equal(kv.issuer, 'https://accounts.google.com');
  assert.equal(kv.root, 'sigstore-public');
  assert.equal(kv.integratedTime, 1785694741);
  assert.equal(JSON.parse(kv.payload.toString('utf8')).name, 'sess_plan');
});

test('the public-good bundle fails when any stapled part is altered', () => {
  const sig = realBundle();
  sig.envelope.payload = Buffer.from('{"schema":"x"}').toString('base64');
  assert.throws(() => verifyKeylessWith(sig, [publicRoot()]), /signature verification failed/);

  const set = realBundle();
  set.transparency.logIndex += 1;
  assert.throws(
    () => verifyKeylessWith(set, [publicRoot()]),
    /signed entry timestamp verification failed/,
  );

  const hint = realBundle();
  hint.signer.identity = 'mallory@example.com';
  assert.throws(
    () => verifyKeylessWith(hint, [publicRoot()]),
    /signer\.identity "mallory@example\.com" does not match certificate identity "info@promptsign\.ai"/,
  );

  const chain = realBundle();
  chain.signer.certChain = chain.signer.certChain.slice(0, 1);
  // The leaf alone still chains to the pinned intermediate.
  assert.equal(verifyKeylessWith(chain, [publicRoot()]).root, 'sigstore-public');

  assert.throws(
    () => verifyKeylessWith(realBundle(), []),
    /does not terminate at a trusted root: it ends at "CN=sigstore,O=sigstore.dev"/,
  );
});

// ---- synthetic chains --------------------------------------------------

const T = 1790834400; // integratedTime: 2026-10-01T06:00:00Z
const DAY = 86400;
const PAYLOAD = Buffer.from(
  JSON.stringify({ schema: 'promptsign/manifest/v1', name: 'x', scope: 'file', files: [] }),
);

// A CA, an optional intermediate, and a leaf; returns a bundle and the
// trusted_root.json for the CA, both adjustable per test.
function scenario({
  leafKind = 'p256',
  inter = false,
  caExts = [ext.basicConstraints(true), ext.keyUsage(5)],
  interExts = [ext.basicConstraints(true, 0), ext.keyUsage(5)],
  leafExts = [ext.sanEmail('alice@corp.test'), ext.fulcioIssuer('https://sso.corp.test')],
  leafWindow = [T - 300, T + 300],
  t = T,
  rootOpts = {},
} = {}) {
  const ca = p256();
  const log = p256();
  const caDer = makeCert({
    subject: cn('root'),
    issuer: cn('root'),
    key: ca.publicKey,
    signer: ca.privateKey,
    notBefore: T - 365 * DAY,
    notAfter: T + 365 * DAY,
    exts: caExts,
  });
  let issuerName = cn('root');
  let issuerKey = ca.privateKey;
  const chain = [];
  if (inter) {
    const mid = p256();
    chain.push(
      makeCert({
        subject: cn('inter'),
        issuer: cn('root'),
        key: mid.publicKey,
        signer: ca.privateKey,
        notBefore: T - DAY,
        notAfter: T + DAY,
        exts: interExts,
      }),
    );
    issuerName = cn('inter');
    issuerKey = mid.privateKey;
  }
  const leaf = leafKind === 'p256' ? p256() : ed25519();
  chain.unshift(
    makeCert({
      subject: cn('leaf'),
      issuer: issuerName,
      key: leaf.publicKey,
      signer: issuerKey,
      notBefore: leafWindow[0],
      notAfter: leafWindow[1],
      exts: leafExts,
    }),
  );
  const bundle = keylessBundle({
    chain,
    leafKey: leaf.privateKey,
    logKey: log.privateKey,
    t,
    payload: PAYLOAD,
  });
  const doc = trustedRoot(caDer, log.publicKey, rootOpts);
  return { bundle, doc, leafDer: chain[0], log };
}

const verify = (s, name = 'corp') =>
  verifyKeylessWith(s.bundle, [rootFromTrustedRoot(name, s.doc)]);

test('a P-256 leaf (cosign interop) verifies: identity, issuer, root, time, keyid', () => {
  const s = scenario();
  const kv = verify(s);
  assert.equal(kv.identity, 'alice@corp.test');
  assert.equal(kv.issuer, 'https://sso.corp.test');
  assert.equal(kv.root, 'corp');
  assert.equal(kv.integratedTime, T);
  assert.ok(kv.payload.equals(PAYLOAD));
  // The keyid is the leaf's SPKI digest.
  assert.equal(kv.leafKeyid.length, 64);
});

test('an Ed25519 leaf under an intermediate verifies', () => {
  const kv = verify(scenario({ leafKind: 'ed25519', inter: true }));
  assert.equal(kv.identity, 'alice@corp.test');
});

test('a URI identity and the legacy Fulcio issuer extension are read', () => {
  const kv = verify(
    scenario({
      leafExts: [
        ext.sanUri('https://github.com/acme/x/.github/workflows/s.yml@refs/tags/v1'),
        ext.fulcioIssuerV1('https://token.actions.githubusercontent.com'),
      ],
    }),
  );
  assert.equal(kv.identity, 'https://github.com/acme/x/.github/workflows/s.yml@refs/tags/v1');
  assert.equal(kv.issuer, 'https://token.actions.githubusercontent.com');
});

test('issuing certificates must be CAs within their path length and key usage', () => {
  assert.throws(
    () => verify(scenario({ inter: true, interExts: [ext.basicConstraints(false)] })),
    /^Error: "CN=inter" issues certificates but is not a CA$/,
  );
  assert.throws(
    () => verify(scenario({ inter: true, interExts: [ext.keyUsage(5)] })),
    /"CN=inter" issues certificates but has no basic constraints/,
  );
  assert.throws(
    () =>
      verify(scenario({ inter: true, interExts: [ext.basicConstraints(true), ext.keyUsage(0)] })),
    /"CN=inter" issues certificates without the keyCertSign usage/,
  );
  assert.throws(
    () =>
      verify(scenario({ inter: true, caExts: [ext.basicConstraints(true, 0), ext.keyUsage(5)] })),
    /"CN=root" allows 0 CA certificates beneath it, the chain has 1/,
  );
});

test('integratedTime must fall inside the leaf validity', () => {
  assert.throws(
    () => verify(scenario({ leafWindow: [T + 1, T + 600] })),
    new RegExp(`log integration time ${T} outside certificate validity \\[${T + 1}, ${T + 600}\\]`),
  );
});

test("integratedTime must fall inside the CA's and the log's validFor", () => {
  const iso = formatIso8601;
  assert.throws(
    () => verify(scenario({ rootOpts: { caValid: { start: iso(T - DAY), end: iso(T) } } })),
    new RegExp(
      `certificate authority "CN=root" of trust root "corp" was outside its validity window when the log witnessed the signature \\(integratedTime ${T}\\)`,
    ),
  );
  assert.throws(
    () => verify(scenario({ rootOpts: { logValid: { start: iso(T + 1) } } })),
    /transparency log [0-9a-f]{16}… of trust root "corp" was outside its validity window at integratedTime/,
  );
  // [start, end): the last second before the end still verifies.
  const s = scenario({ rootOpts: { caValid: { start: iso(T - DAY), end: iso(T + 1) } } });
  assert.equal(verify(s).root, 'corp');
});

test('a CA listed under several entries verifies when any entry window holds', () => {
  const s = scenario();
  const iso = formatIso8601;
  const ca = s.doc.certificateAuthorities[0];
  s.doc.certificateAuthorities = [
    { ...ca, validFor: { start: iso(T - 2 * DAY), end: iso(T - DAY) } },
    { ...ca, validFor: { start: iso(T - DAY) } },
  ];
  assert.equal(verify(s).root, 'corp');
});

test("the entry's log must belong to the anchor root, and a CA-only root never anchors keyless", () => {
  const s = scenario();
  const other = scenario();
  // Same CA, but the root names a different log key.
  s.doc.tlogs = other.doc.tlogs;
  assert.throws(() => verify(s), /transparency logId [0-9a-f]{64} does not match any trusted log/);
  const caOnly = scenario();
  caOnly.doc.tlogs = [];
  assert.throws(() => verify(caOnly), /does not terminate at a trusted root/);
});

test('roots are tried in order and the first that verifies names the result', () => {
  const s = scenario();
  const iso = formatIso8601;
  const closed = structuredClone(s.doc);
  closed.certificateAuthorities[0].validFor = { start: iso(T - 2 * DAY), end: iso(T - DAY) };
  const kv = verifyKeylessWith(s.bundle, [
    rootFromTrustedRoot('acme/old', closed),
    rootFromTrustedRoot('acme/new', s.doc),
  ]);
  assert.equal(kv.root, 'acme/new');
  // Only the closed one: its window error is reported.
  assert.throws(
    () => verifyKeylessWith(s.bundle, [rootFromTrustedRoot('acme/old', closed)]),
    /of trust root "acme\/old" was outside its validity window/,
  );
});

test('the transparency entry must bind this payload and signature', () => {
  const s = scenario();
  const body = JSON.parse(Buffer.from(s.bundle.transparency.body, 'base64').toString('utf8'));
  body.spec.payloadHash.value = sha256(Buffer.from('other'));
  const bad = { ...s, bundle: structuredClone(s.bundle) };
  bad.bundle.transparency.body = Buffer.from(JSON.stringify(body)).toString('base64');
  // The SET no longer covers the body, so that check fails first.
  assert.throws(() => verify(bad), /signed entry timestamp verification failed/);
  const missing = structuredClone(s.bundle);
  delete missing.transparency;
  assert.throws(
    () => verifyKeylessWith(missing, [rootFromTrustedRoot('corp', s.doc)]),
    /keyless bundle missing transparency block/,
  );
});
