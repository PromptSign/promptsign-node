// Rekor v2 log evidence (spec/05 §3.2): an RFC 6962 inclusion proof of the
// entry against a checkpoint the log signed. A checkpoint is a C2SP signed
// note: origin, tree size and base64 root hash, one per line, a blank line,
// then one "— <name> <base64(key hint || signature)>" line per signer.
// Witness cosignatures may follow; signers the verifier does not know are
// ignored. Mirrors promptsign-core's logproof.rs, messages included.

import crypto from 'node:crypto';
import { b64decode } from './util.mjs';

// Verify a signed-note checkpoint with `log`'s key. Returns { size, rootHash }.
export function verifyCheckpoint(note, log) {
  const origin = log.origin();
  if (origin === null) {
    throw new Error('transparency log has no baseUrl, so its checkpoint origin is unknown');
  }
  const split = note.indexOf('\n\n');
  if (split === -1) throw new Error('checkpoint: no signature block');
  const text = note.slice(0, split + 1);
  const sigs = note.slice(split + 2);
  const lines = text.slice(0, -1).split('\n');
  if (lines.length < 3) throw new Error('checkpoint: needs origin, size and root hash lines');
  if (lines[0] !== origin) {
    throw new Error(`checkpoint origin "${lines[0]}" is not the log's origin "${origin}"`);
  }
  const size = parseSize(lines[1]);
  const rootHash = b64decode(lines[2]);
  if (!rootHash || rootHash.length !== 32) {
    throw new Error('checkpoint: root hash is not 32 bytes of base64');
  }
  if (sigs.length === 0 || !sigs.endsWith('\n')) {
    throw new Error('checkpoint: malformed signature block');
  }
  const hint = log.keyHint();
  let verified = false;
  for (const line of sigs.slice(0, -1).split('\n')) {
    if (!line.startsWith('— ')) throw new Error('checkpoint: malformed signature line');
    const rest = line.slice(2);
    const sp = rest.indexOf(' ');
    if (sp === -1) throw new Error('checkpoint: malformed signature line');
    const name = rest.slice(0, sp);
    const raw = b64decode(rest.slice(sp + 1));
    if (!raw) throw new Error('checkpoint: signature is not base64');
    if (raw.length < 5) throw new Error('checkpoint: signature too short');
    if (name !== origin || !raw.subarray(0, 4).equals(hint)) continue;
    verifyNoteSignature(log, Buffer.from(text), raw.subarray(4));
    verified = true;
  }
  if (!verified) throw new Error(`checkpoint carries no signature from log "${origin}"`);
  return { size, rootHash };
}

function parseSize(s) {
  const ok = /^\d+$/.test(s) && (s === '0' || !s.startsWith('0'));
  const n = ok ? BigInt(s) : null;
  if (n === null || n > 0xffffffffffffffffn) {
    throw new Error(`checkpoint: tree size "${s}" is not a number`);
  }
  return n;
}

// Ed25519 signs the note text directly; ECDSA signs its SHA-256, DER encoded.
function verifyNoteSignature(log, text, sig) {
  let ok = false;
  try {
    ok =
      log.keyType === 'ed25519'
        ? sig.length === 64 && crypto.verify(null, text, log.key, sig)
        : crypto.verify('sha256', text, { key: log.key, dsaEncoding: 'der' }, sig);
  } catch {
    ok = false;
  }
  if (!ok) throw new Error('checkpoint signature by the log does not verify');
}

// RFC 6962 leaf hash of a canonicalized entry body.
export function leafHash(body) {
  return crypto
    .createHash('sha256')
    .update(Buffer.from([0]))
    .update(body)
    .digest();
}

function nodeHash(left, right) {
  return crypto
    .createHash('sha256')
    .update(Buffer.from([1]))
    .update(left)
    .update(right)
    .digest();
}

// RFC 9162 §2.1.3.2: does `proof` take the leaf at `index` to `root` in a
// tree of `size` leaves? Indexes are BigInt.
export function verifyInclusion(index, size, leaf, proof, root) {
  if (index >= size) {
    throw new Error(`inclusion proof: index ${index} is outside a tree of size ${size}`);
  }
  let fn = index;
  let sn = size - 1n;
  let r = leaf;
  for (const p of proof) {
    if (p.length !== 32) throw new Error('inclusion proof: hash is not 32 bytes');
    if (sn === 0n) throw new Error('inclusion proof: too many hashes');
    if ((fn & 1n) === 1n || fn === sn) {
      r = nodeHash(p, r);
      while ((fn & 1n) === 0n && fn !== 0n) {
        fn >>= 1n;
        sn >>= 1n;
      }
    } else {
      r = nodeHash(r, p);
    }
    fn >>= 1n;
    sn >>= 1n;
  }
  if (sn !== 0n) throw new Error('inclusion proof: too few hashes');
  if (!r.equals(root)) {
    throw new Error("inclusion proof does not lead to the checkpoint's root hash");
  }
}
