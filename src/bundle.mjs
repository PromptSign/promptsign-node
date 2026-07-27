// Dead Simple Signing Envelope (DSSE) signing/verification over the manifest (spec/03-bundle.md).
// Detached carriage: <dir>/.promptsign/bundle.json for directories,
// <file>.psig.json for standalone files.

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { sha256 } from './canonicalize.mjs';
import { MANIFEST_SCHEMA } from './manifest.mjs';

export const BUNDLE_SCHEMA = 'promptsign/bundle/v1';
export const PAYLOAD_TYPE = 'application/vnd.promptsign.manifest+json';

// DSSE pre-authentication encoding: binds payloadType to the payload so an
// envelope cannot be replayed as a different content type.
export function pae(payloadType, payload) {
  return Buffer.concat([
    Buffer.from(
      `DSSEv1 ${Buffer.byteLength(payloadType)} ${payloadType} ${payload.length} `,
      'utf8',
    ),
    payload,
  ]);
}

export function signManifest(manifest, privateKey, identity) {
  const payload = Buffer.from(JSON.stringify(manifest), 'utf8');
  const publicKey = crypto.createPublicKey(privateKey);
  const spkiDer = publicKey.export({ type: 'spki', format: 'der' });
  const sig = crypto.sign(null, pae(PAYLOAD_TYPE, payload), privateKey);
  return {
    schema: BUNDLE_SCHEMA,
    envelope: {
      payloadType: PAYLOAD_TYPE,
      payload: payload.toString('base64'),
      signatures: [{ keyid: sha256(spkiDer), sig: sig.toString('base64') }],
    },
    signer: {
      identity,
      scheme: 'ed25519',
      publicKey: spkiDer.toString('base64'),
    },
  };
}

// Cryptographic verification only — integrity against disk and trust policy
// are separate, later steps. Throws on any envelope problem.
export function verifyEnvelope(bundle) {
  if (bundle?.schema !== BUNDLE_SCHEMA)
    throw new Error(`unsupported bundle schema: ${bundle?.schema}`);
  const { envelope, signer } = bundle;
  if (envelope?.payloadType !== PAYLOAD_TYPE) {
    throw new Error(`unsupported payload type: ${envelope?.payloadType}`);
  }
  if (signer?.scheme !== 'ed25519')
    throw new Error(`unsupported signature scheme: ${signer?.scheme}`);
  const spkiDer = Buffer.from(signer.publicKey, 'base64');
  const publicKey = crypto.createPublicKey({ key: spkiDer, format: 'der', type: 'spki' });
  const keyid = sha256(spkiDer);
  const entry = (envelope.signatures || []).find((s) => s.keyid === keyid);
  if (!entry) throw new Error('no signature matching the embedded public key');
  const payload = Buffer.from(envelope.payload, 'base64');
  const ok = crypto.verify(
    null,
    pae(envelope.payloadType, payload),
    publicKey,
    Buffer.from(entry.sig, 'base64'),
  );
  if (!ok) throw new Error('signature verification failed');
  const manifest = JSON.parse(payload.toString('utf8'));
  if (manifest.schema !== MANIFEST_SCHEMA)
    throw new Error(`unsupported manifest schema: ${manifest.schema}`);
  return { manifest, identity: signer.identity ?? `key:${keyid.slice(0, 16)}`, keyid };
}

export function bundlePathFor(target) {
  const st = fs.statSync(target);
  if (st.isDirectory()) return path.join(target, '.promptsign', 'bundle.json');
  return target + '.psig.json';
}

export function writeBundle(target, bundle) {
  const p = bundlePathFor(target);
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, JSON.stringify(bundle, null, 2) + '\n');
  return p;
}

export function readBundle(target) {
  const p = bundlePathFor(target);
  if (!fs.existsSync(p)) return null;
  return { bundle: JSON.parse(fs.readFileSync(p, 'utf8')), path: p };
}

// Frontmatter content lines (between the opening and closing `---`), with line
// endings normalized and CRs stripped. null if the text has no frontmatter.
function frontmatterLines(mdText) {
  const text = mdText.startsWith('﻿') ? mdText.slice(1) : mdText;
  const norm = text.replaceAll('\r\n', '\n').replaceAll('\r', '\n');
  if (!norm.startsWith('---\n')) return null;
  const body = norm.slice(4);
  const end = body.indexOf('\n---');
  if (end === -1) return null;
  return body.slice(0, end).split('\n');
}

// True iff the YAML frontmatter carries an `x-promptsign:` marker line. Cheap
// scan (no decode) used to reject markers in context-injected files.
export function hasSignatureMarker(mdText) {
  const lines = frontmatterLines(mdText);
  return lines !== null && lines.some((l) => l.startsWith('x-promptsign:'));
}
