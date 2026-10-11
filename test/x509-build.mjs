// Test helper: a tiny DER encoder and X.509 certificate builder, enough to
// make synthetic CA chains (P-256 and Ed25519 keys, chosen extensions) and
// keyless bundles signed through them. Not a test file itself.

import crypto from 'node:crypto';
import { pae, PAYLOAD_TYPE } from '../src/bundle.mjs';
import { sha256 } from '../src/canonicalize.mjs';

export function tlv(tag, ...parts) {
  const body = Buffer.concat(parts);
  const n = body.length;
  let len;
  if (n < 0x80) len = Buffer.from([n]);
  else if (n < 0x100) len = Buffer.from([0x81, n]);
  else len = Buffer.from([0x82, n >> 8, n & 0xff]);
  return Buffer.concat([Buffer.from([tag]), len, body]);
}

export const seq = (...p) => tlv(0x30, ...p);
export const set = (...p) => tlv(0x31, ...p);
export const utf8 = (s) => tlv(0x0c, Buffer.from(s, 'utf8'));
export const printable = (s) => tlv(0x13, Buffer.from(s, 'latin1'));
export const octet = (b) => tlv(0x04, b);
export const bool = (v) => tlv(0x01, Buffer.from([v ? 0xff : 0]));
export const bitString = (b, unused = 0) => tlv(0x03, Buffer.from([unused]), b);

export function int(n) {
  const bytes = [];
  do {
    bytes.unshift(n & 0xff);
    n = Math.floor(n / 256);
  } while (n > 0);
  if (bytes[0] & 0x80) bytes.unshift(0);
  return tlv(0x02, Buffer.from(bytes));
}

export function oid(dotted) {
  const arcs = dotted.split('.').map(Number);
  const out = [];
  for (const a of [arcs[0] * 40 + arcs[1], ...arcs.slice(2)]) {
    const groups = [];
    let v = a;
    do {
      groups.unshift(v & 0x7f);
      v = Math.floor(v / 128);
    } while (v > 0);
    out.push(...groups.map((g, i) => (i < groups.length - 1 ? g | 0x80 : g)));
  }
  return tlv(0x06, Buffer.from(out));
}

// Seconds since the epoch as GeneralizedTime (YYYYMMDDHHMMSSZ).
export function genTime(secs) {
  const s = new Date(secs * 1000).toISOString().replace(/[-:T]/g, '').slice(0, 14) + 'Z';
  return tlv(0x18, Buffer.from(s, 'latin1'));
}

// A Name from [[oid, value], ...] pairs, one RDN each, in order.
export function name(pairs) {
  return seq(...pairs.map(([o, v]) => set(seq(oid(o), utf8(v)))));
}

export const cn = (v) => name([['2.5.4.3', v]]);

export const ext = {
  basicConstraints: (ca, pathLen) => [
    '2.5.29.19',
    seq(...(ca ? [bool(true)] : []), ...(pathLen === undefined ? [] : [int(pathLen)])),
  ],
  // Key usage bits by number (0 = digitalSignature, 5 = keyCertSign).
  keyUsage: (...bits) => {
    const b = Buffer.alloc(2);
    for (const n of bits) b[n >> 3] |= 0x80 >> (n & 7);
    return ['2.5.29.15', bitString(b)];
  },
  extKeyUsage: (...oids) => ['2.5.29.37', seq(...oids.map(oid))],
  sanEmail: (email) => ['2.5.29.17', seq(tlv(0x81, Buffer.from(email)))],
  sanUri: (uri) => ['2.5.29.17', seq(tlv(0x86, Buffer.from(uri)))],
  fulcioIssuer: (iss) => ['1.3.6.1.4.1.57264.1.8', utf8(iss)],
  fulcioIssuerV1: (iss) => ['1.3.6.1.4.1.57264.1.1', Buffer.from(iss)],
};

function sigAlgFor(key) {
  return key.asymmetricKeyType === 'ed25519'
    ? { oid: '1.3.101.112', hash: null }
    : { oid: '1.2.840.10045.4.3.2', hash: 'sha256' };
}

// One certificate: `key` is the subject's public key, `signer` the issuer's
// private key. Returns the DER.
export function makeCert({ subject, issuer, key, signer, notBefore, notAfter, exts = [] }) {
  const alg = sigAlgFor(signer);
  const algId = seq(oid(alg.oid));
  const spki = key.export({ type: 'spki', format: 'der' });
  const extBlock = exts.length
    ? [tlv(0xa3, seq(...exts.map(([o, v]) => seq(oid(o), octet(v)))))]
    : [];
  const tbs = seq(
    tlv(0xa0, int(2)),
    int(1),
    algId,
    issuer,
    seq(genTime(notBefore), genTime(notAfter)),
    subject,
    spki,
    ...extBlock,
  );
  const sig = crypto.sign(alg.hash, tbs, signer);
  return seq(tbs, algId, bitString(sig));
}

export const p256 = () => crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
export const ed25519 = () => crypto.generateKeyPairSync('ed25519');

// A trusted_root.json document for one CA certificate and one log key.
export function trustedRoot(caDer, logPublic, { caValid, logValid } = {}) {
  const ca = { certChain: { certificates: [{ rawBytes: caDer.toString('base64') }] } };
  if (caValid) ca.validFor = caValid;
  const publicKey = {
    rawBytes: logPublic.export({ type: 'spki', format: 'der' }).toString('base64'),
    keyDetails: 'PKIX_ECDSA_P256_SHA_256',
  };
  if (logValid) publicKey.validFor = logValid;
  return {
    mediaType: 'application/vnd.dev.sigstore.trustedroot+json;version=0.1',
    certificateAuthorities: [ca],
    tlogs: [{ publicKey }],
  };
}

// A keyless bundle over `payload`, signed by `leafKey` (private) with the
// given leaf-first chain, witnessed by `logKey` (private) at time `t`.
export function keylessBundle({ chain, leafKey, logKey, t, payload, identity, issuer }) {
  const hash = leafKey.asymmetricKeyType === 'ed25519' ? null : 'sha256';
  const sig = crypto.sign(hash, pae(PAYLOAD_TYPE, payload), leafKey).toString('base64');
  const body = Buffer.from(
    JSON.stringify({
      apiVersion: '0.0.1',
      kind: 'dsse',
      spec: {
        payloadHash: { algorithm: 'sha256', value: sha256(payload) },
        signatures: [{ signature: sig }],
      },
    }),
  ).toString('base64');
  const logId = sha256(crypto.createPublicKey(logKey).export({ type: 'spki', format: 'der' }));
  const canonical = `{"body":${JSON.stringify(body)},"integratedTime":${t},"logID":${JSON.stringify(logId)},"logIndex":7}`;
  const set = crypto.sign('sha256', Buffer.from(canonical), logKey).toString('base64');
  const signer = { scheme: 'keyless', certChain: chain.map((c) => c.toString('base64')) };
  if (identity) signer.identity = identity;
  if (issuer) signer.issuer = issuer;
  return {
    schema: 'promptsign/bundle/v1',
    envelope: {
      payloadType: PAYLOAD_TYPE,
      payload: payload.toString('base64'),
      signatures: [{ keyid: '', sig }],
    },
    signer,
    transparency: { logId, logIndex: 7, integratedTime: t, signedEntryTimestamp: set, body },
  };
}
