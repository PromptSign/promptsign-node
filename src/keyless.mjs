// Offline verification of keyless (Sigstore-style) bundles per
// spec/05-keyless.md §4: stapled certificate chain to a trusted root (spec/07
// §3.1), SAN identity and Fulcio issuer from the leaf, and the log's proof: a
// Rekor v1 signed entry timestamp, or a Rekor v2 inclusion proof with RFC 3161
// timestamps. No network anywhere. Mirrors promptsign-core's keyless.rs.

import crypto from 'node:crypto';
import fs from 'node:fs';
import { pae } from './bundle.mjs';
import { sha256 } from './canonicalize.mjs';
import { anchorChain, verifyLeafSignature } from './chain.mjs';
import {
  OID,
  TAG,
  children,
  decodeOne,
  isEcdsaSigDer,
  parseCertificate,
  pemBodies,
  sanIdentity,
  utf8String,
} from './der.mjs';
import { promptsignHome } from './keys.mjs';
import { envOverride } from './managed.mjs';
import { leafHash, verifyCheckpoint, verifyInclusion } from './logproof.mjs';
import { loadRegistry, openWindow } from './trustroot.mjs';
import { MAX_TIMESTAMPS, verifyTimestamp } from './tsa.mjs';
import { b64decode, joinRaw } from './util.mjs';

// $PROMPTSIGN_TRUST_DIR (unless the managed policy locks the environment),
// else $PROMPTSIGN_HOME/trust: where the built-in root's fulcio.pem and
// rekor.pub live.
export function trustDir() {
  return envOverride('PROMPTSIGN_TRUST_DIR') || joinRaw(promptsignHome(), 'trust');
}

// The host of an http(s) URL, without user info or port; null when empty.
export function hostOf(url) {
  const i = url.indexOf('://');
  const rest = i === -1 ? url : url.slice(i + 3);
  const authority = rest.split(/[/?#]/)[0];
  let host = authority.slice(authority.lastIndexOf('@') + 1);
  const colon = host.lastIndexOf(':');
  if (colon !== -1 && /^\d+$/.test(host.slice(colon + 1))) host = host.slice(0, colon);
  return host === '' ? null : host;
}

// The methods every log carries: the checkpoint origin, the four-byte key
// hint a checkpoint signature line names the key by, and its key type.
function logMethods(log) {
  return {
    ...log,
    origin() {
      return this.baseUrl ? hostOf(this.baseUrl) : null;
    },
    keyHint() {
      return Buffer.from(this.logId.slice(0, 8), 'hex');
    },
    keyDetails() {
      return this.keyType === 'ed25519' ? 'PKIX_ED25519' : 'PKIX_ECDSA_P256_SHA_256';
    },
  };
}

// An Ed25519 (Rekor v2) log, which needs its base URL: the log id is the C2SP
// signed-note key hash, which covers the origin (spec/07 §1).
export function rekorLogEd25519(der, baseUrl) {
  let key;
  try {
    key = crypto.createPublicKey({ key: der, format: 'der', type: 'spki' });
    if (key.asymmetricKeyType !== 'ed25519') throw new Error('not an Ed25519 key');
  } catch (e) {
    throw new Error(`invalid Ed25519 public key: ${e.message}`);
  }
  const origin = hostOf(baseUrl);
  if (origin === null) throw new Error(`log baseUrl "${baseUrl}" has no host`);
  const raw = key.export({ format: 'jwk' }).x;
  const logId = crypto
    .createHash('sha256')
    .update(origin)
    .update(Buffer.from([0x0a, 0x01]))
    .update(Buffer.from(raw, 'base64url'))
    .digest('hex');
  return logMethods({
    key,
    keyType: 'ed25519',
    logId,
    spkiDer: Buffer.from(der),
    valid: openWindow(),
    baseUrl,
  });
}

// One transparency log: its P-256 key and the log id (hex SHA-256 of the
// key's SPKI DER) every entry it witnesses carries.
export function rekorLogFromSpki(der) {
  let key;
  try {
    const [alg] = children(decodeOne(der, TAG.SEQUENCE).content);
    const [oid, curve] = children(alg.content);
    if (
      oid.content.toString('hex') !== '2a8648ce3d0201' ||
      curve?.content.toString('hex') !== '2a8648ce3d030107'
    ) {
      throw new Error('not a P-256 key');
    }
    key = crypto.createPublicKey({ key: der, format: 'der', type: 'spki' });
  } catch (e) {
    throw new Error(`invalid P-256 public key: ${e.message}`);
  }
  return logMethods({
    key,
    keyType: 'p256',
    logId: sha256(der),
    spkiDer: Buffer.from(der),
    valid: openWindow(),
    baseUrl: null,
  });
}

// Every trusted log in a rekor.pub, one PEM PUBLIC KEY block each, oldest
// first. Rotation appends, so older entries keep verifying.
export function parseRekorLogs(pem) {
  const ders = pemBodies(pem, 'PUBLIC KEY');
  if (ders.length === 0) throw new Error('no PUBLIC KEY block');
  return ders.map(rekorLogFromSpki);
}

// The pinned pair alone, for `trust fetch` and `trust show`.
export function trustedLogIds() {
  const dir = trustDir();
  const rekor = joinRaw(dir, 'rekor.pub');
  if (!fs.existsSync(joinRaw(dir, 'fulcio.pem')) || !fs.existsSync(rekor)) {
    throw new Error(`no Sigstore trust root in ${dir} — run "promptsign trust fetch" first`);
  }
  try {
    return parseRekorLogs(fs.readFileSync(rekor, 'utf8')).map((l) => l.logId);
  } catch (e) {
    throw new Error(`${rekor}: ${e.message}`);
  }
}

// (identity, issuer) from a Fulcio-style leaf certificate.
export function leafIdentity(leaf) {
  if (leaf.extensions.length === 0) throw new Error('leaf certificate has no extensions');
  let identity = null;
  let issuer = null;
  for (const ext of leaf.extensions) {
    if (ext.oid === OID.SAN) {
      try {
        identity = sanIdentity(ext.value) ?? identity;
      } catch (e) {
        throw new Error(`SAN parse: ${e.message}`);
      }
    } else if (ext.oid === OID.FULCIO_ISSUER_V2) {
      try {
        issuer = utf8String(ext.value);
      } catch (e) {
        throw new Error(`issuer ext parse: ${e.message}`);
      }
    } else if (ext.oid === OID.FULCIO_ISSUER_V1 && issuer === null) {
      issuer = ext.value.toString('utf8');
    }
  }
  if (identity === null) throw new Error('leaf certificate has no SAN identity');
  if (issuer === null) throw new Error('leaf certificate has no Fulcio issuer extension');
  return { identity, issuer };
}

// The registry's keyless roots (those with logs). Errors when there are
// none, since keyless verification is then impossible.
export function keylessRoots() {
  const roots = loadRegistry().filter((r) => r.rekorLogs.length > 0);
  if (roots.length === 0) {
    throw new Error(`no Sigstore trust root in ${trustDir()}: run "promptsign trust fetch" first`);
  }
  return roots;
}

// The validity windows of spec/07 §4 at signing time `t`: every CA on the
// path that the root lists, under any of its entries, and the log key that
// witnessed it.
function checkWindows(a, log, t) {
  const ca = a.root.caOutsideWindow(a.path, t);
  if (ca) {
    throw new Error(
      `certificate authority "${ca.subject}" of trust root "${a.root.name}" was outside its validity window when the signature was made (${t})`,
    );
  }
  if (!log.valid.contains(t)) {
    throw new Error(
      `transparency log ${log.logId.slice(0, 16)}… of trust root "${a.root.name}" was outside its validity window when the signature was made (${t})`,
    );
  }
}

const str = (v) => (typeof v === 'string' ? v : undefined);

// Every RFC 3161 timestamp in the bundle that verifies against `root`'s
// timestamp authorities, over the envelope signature `sig`. One that does
// not verify is no time evidence; the first such error explains a bundle
// left with none.
export function verifiedTimes(timestamps, sig, root) {
  if (timestamps.length > MAX_TIMESTAMPS) {
    throw new Error(`bundle carries ${timestamps.length} timestamps, more than ${MAX_TIMESTAMPS}`);
  }
  const times = [];
  let error = null;
  for (const ts of timestamps) {
    try {
      times.push(verifyTimestamp(ts, sig, root.tsas).time);
    } catch (e) {
      error ??= e;
    }
  }
  return { times, error };
}

// Offline keyless verification per spec/05 §4, independent of how the bundle
// carries its parts: the chain must end at a keyless root, the leaf must have
// signed the DSSE envelope, one of that root's logs must hold the entry, and
// the leaf must have been valid at every verified signing time. `env` is
// { payloadType, payload, sig, sigB64 }.
export function verifyKeylessParts(chain, env, tlog, timestamps, roots) {
  const anchored = anchorChain(
    chain,
    roots.filter((r) => r.rekorLogs.length > 0),
  );
  const leaf = chain[0];

  // envelope signature (step 1)
  verifyLeafSignature(leaf, pae(env.payloadType, env.payload), env.sig);

  // The entry names the log that witnessed it; only the logs of a root the
  // chain ends at count. After a key rotation both keys are pinned, so old
  // entries keep verifying.
  let firstError = null;
  for (const a of anchored) {
    for (const log of a.root.rekorLogs.filter((l) => l.logId === tlog.logId)) {
      let time;
      try {
        time = verifyWithLog(a, log, leaf, env, tlog, timestamps);
      } catch (e) {
        firstError ??= e;
        continue;
      }
      const { identity, issuer } = leafIdentity(leaf);
      return {
        identity,
        issuer,
        leafKeyid: sha256(leaf.spkiDer),
        root: a.root.name,
        integratedTime: time,
      };
    }
  }
  if (firstError) throw firstError;
  const trusted = anchored.flatMap((a) => a.root.rekorLogs).map((l) => l.logId.slice(0, 16));
  throw new Error(
    `transparency logId ${tlog.logId} does not match any trusted log (trusted: ${trusted.join('…, ')}…)`,
  );
}

// Steps 3 to 5 for one candidate log: the log's proof, the entry binding, and
// the certificate's validity at each signing time. Returns the time the
// signature was witnessed.
function verifyWithLog(a, log, leaf, env, tlog, timestamps) {
  const bodyRaw = b64decode(tlog.bodyB64);
  if (!bodyRaw) throw new Error('invalid base64 in body');
  let body;
  try {
    body = JSON.parse(bodyRaw.toString('utf8'));
  } catch (e) {
    throw new Error(`entry body: ${e.message}`);
  }

  // log proof (step 3) and entry binding (step 4)
  let witnessed = null;
  if (tlog.proof.setB64 !== undefined) {
    verifySet(log, tlog, tlog.proof.integratedTime, tlog.proof.setB64);
    bindDsseV001(body, env);
    witnessed = tlog.proof.integratedTime;
  } else {
    const cp = verifyCheckpoint(tlog.proof.checkpoint, log);
    if (cp.size !== tlog.proof.treeSize || !cp.rootHash.equals(tlog.proof.rootHash)) {
      throw new Error('inclusion proof does not match its checkpoint');
    }
    if (tlog.logIndex < 0) throw new Error('negative logIndex');
    verifyInclusion(
      BigInt(tlog.logIndex),
      cp.size,
      leafHash(bodyRaw),
      tlog.proof.hashes,
      cp.rootHash,
    );
    bindHashedrekordV002(body, leaf, env);
  }

  // time validity (step 5)
  const { times, error } = verifiedTimes(timestamps, env.sig, a.root);
  if (witnessed !== null) times.push(witnessed);
  if (times.length === 0) {
    throw new Error(
      error
        ? `no verified signing time: ${error.message}`
        : 'no verified signing time: the log entry carries none and the bundle has no timestamp',
    );
  }
  for (const t of times) {
    if (t < leaf.notBefore || t > leaf.notAfter) {
      throw new Error(
        `signing time ${t} outside certificate validity [${leaf.notBefore}, ${leaf.notAfter}]`,
      );
    }
    checkWindows(a, log, t);
  }
  return witnessed ?? Math.min(...times);
}

// Rekor v1: the SET is the log's ECDSA signature over the canonical entry.
function verifySet(log, tlog, integratedTime, setB64) {
  if (log.keyType !== 'p256') {
    throw new Error('signed entry timestamp from a log without a P-256 key');
  }
  const canonical =
    `{"body":${JSON.stringify(tlog.bodyB64)},"integratedTime":${integratedTime},` +
    `"logID":${JSON.stringify(tlog.logId)},"logIndex":${tlog.logIndex}}`;
  const set = b64decode(setB64);
  if (!set) throw new Error('invalid base64 in signedEntryTimestamp');
  if (!isEcdsaSigDer(set)) throw new Error('malformed SET');
  let ok = false;
  try {
    ok = crypto.verify('sha256', Buffer.from(canonical), log.key, set);
  } catch {
    ok = false;
  }
  if (!ok) throw new Error('signed entry timestamp verification failed');
}

const showKind = (k) =>
  k === undefined ? 'undefined' : typeof k === 'string' ? k : JSON.stringify(k);

// A Rekor v1 `dsse` 0.0.1 entry must hash the payload and hold the signature.
function bindDsseV001(body, env) {
  if (body?.kind !== 'dsse') {
    throw new Error(`unexpected transparency entry kind: ${showKind(body?.kind)}`);
  }
  if ((str(body.spec?.payloadHash?.value) ?? '') !== sha256(env.payload)) {
    throw new Error('transparency entry payloadHash does not match envelope payload');
  }
  const entrySigs = Array.isArray(body.spec?.signatures) ? body.spec.signatures : [];
  if (!entrySigs.some((s) => str(s?.signature) === env.sigB64)) {
    throw new Error('transparency entry does not contain the envelope signature');
  }
}

const HASHEDREKORD_DIGESTS = { SHA2_256: 'sha256', SHA2_384: 'sha384', SHA2_512: 'sha512' };

// A Rekor v2 `hashedrekord` 0.0.2 entry must hash PAE(payloadType, payload)
// and hold the signature and the leaf certificate (spec/05 §3.2).
function bindHashedrekordV002(body, leaf, env) {
  if (body?.kind !== 'hashedrekord' || body?.apiVersion !== '0.0.2') {
    throw new Error(
      `unexpected transparency entry kind for an inclusion proof: ${showKind(body?.kind)} ${showKind(body?.apiVersion)}`,
    );
  }
  const spec = body.spec?.hashedRekordV002;
  const b64 = (v, what) => {
    if (typeof v !== 'string') throw new Error(`transparency entry has no ${what}`);
    const out = b64decode(v);
    if (!out) throw new Error(`invalid base64 in transparency entry ${what}`);
    return out;
  };
  const alg = str(spec?.data?.algorithm) ?? 'none';
  const hash = HASHEDREKORD_DIGESTS[alg];
  if (!hash) throw new Error(`unsupported transparency entry digest algorithm: ${alg}`);
  const digest = crypto.createHash(hash).update(pae(env.payloadType, env.payload)).digest();
  if (!b64(spec?.data?.digest, 'digest').equals(digest)) {
    throw new Error('transparency entry digest does not match the signed content');
  }
  if (!b64(spec?.signature?.content, 'signature').equals(env.sig)) {
    throw new Error('transparency entry does not contain the envelope signature');
  }
  if (!b64(spec?.signature?.verifier?.x509Certificate?.rawBytes, 'certificate').equals(leaf.der)) {
    throw new Error('transparency entry names a different certificate');
  }
}

// Full offline keyless verification of a PromptSign bundle (spec/05 §4)
// against every keyless root in the registry. Returns the authenticated
// payload; manifest, integrity and policy are the caller's next steps.
export function verifyKeyless(bundle) {
  return verifyKeylessWith(bundle, keylessRoots());
}

// Base64 strings in a JSON array, decoded. Absent means none.
export function b64List(v, what) {
  return (Array.isArray(v) ? v : []).map((s) => {
    if (typeof s !== 'string') throw new Error(`${what} entry is not a string`);
    const out = b64decode(s);
    if (!out) throw new Error(`invalid base64 in ${what}`);
    return out;
  });
}

// The log proof of a PromptSign `transparency` block (spec/05 §1):
// { integratedTime, setB64 } for Rekor v1, { treeSize, rootHash, hashes,
// checkpoint } for Rekor v2.
function nativeProof(t) {
  if (typeof t.signedEntryTimestamp === 'string') {
    if (!Number.isInteger(t.integratedTime)) throw new Error('transparency.integratedTime missing');
    return { integratedTime: t.integratedTime, setB64: t.signedEntryTimestamp };
  }
  const p = t.inclusionProof;
  if (p === undefined) {
    throw new Error('transparency block has neither signedEntryTimestamp nor inclusionProof');
  }
  if (!Number.isInteger(p?.treeSize) || p.treeSize < 0) {
    throw new Error('inclusionProof.treeSize missing');
  }
  if (typeof p.rootHash !== 'string') throw new Error('inclusionProof.rootHash missing');
  const rootHash = b64decode(p.rootHash);
  if (!rootHash) throw new Error('invalid base64 in inclusionProof.rootHash');
  const hashes = b64List(p.hashes, 'inclusionProof.hashes');
  if (typeof p.checkpoint !== 'string') throw new Error('inclusionProof.checkpoint missing');
  return { treeSize: BigInt(p.treeSize), rootHash, hashes, checkpoint: p.checkpoint };
}

// verifyKeyless against the given roots instead of the registry.
export function verifyKeylessWith(bundle, roots) {
  const chainB64 = bundle?.signer?.certChain;
  if (!Array.isArray(chainB64)) throw new Error('keyless bundle missing signer.certChain');
  const chain = chainB64.map((c) => {
    if (typeof c !== 'string') throw new Error('certChain entry is not a string');
    const der = b64decode(c);
    if (!der) throw new Error('invalid base64 in certChain');
    try {
      return parseCertificate(der);
    } catch (e) {
      throw new Error(`certificate parse: ${e.message}`);
    }
  });
  const payloadType = str(bundle.envelope?.payloadType);
  if (payloadType === undefined) throw new Error('missing envelope.payloadType');
  const payload = b64decode(str(bundle.envelope.payload) ?? '');
  if (!payload) throw new Error('invalid base64 in payload');
  const sigs = bundle.envelope.signatures;
  const sigB64 = Array.isArray(sigs) ? str(sigs[0]?.sig) : undefined;
  if (sigB64 === undefined) throw new Error('missing envelope signature');
  const sig = b64decode(sigB64);
  if (!sig) throw new Error('invalid base64 in signature');
  const env = { payloadType, payload, sig, sigB64 };
  const t = bundle.transparency;
  if (t === undefined) throw new Error('keyless bundle missing transparency block');
  const need = (key, ok) => {
    if (!ok(t?.[key])) throw new Error(`transparency.${key} missing`);
    return t[key];
  };
  const isStr = (v) => typeof v === 'string';
  const tlog = {
    bodyB64: need('body', isStr),
    logId: need('logId', isStr),
    logIndex: need('logIndex', Number.isInteger),
    proof: nativeProof(t),
  };
  const timestamps = b64List(bundle.timestamps, 'timestamps');
  const parts = verifyKeylessParts(chain, env, tlog, timestamps, roots);

  // display-hint check (step 6)
  const idHint = str(bundle.signer.identity);
  if (idHint !== undefined && idHint !== parts.identity) {
    throw new Error(
      `signer.identity "${idHint}" does not match certificate identity "${parts.identity}"`,
    );
  }
  const issHint = str(bundle.signer.issuer);
  if (issHint !== undefined && issHint !== parts.issuer) {
    throw new Error(
      `signer.issuer "${issHint}" does not match certificate issuer "${parts.issuer}"`,
    );
  }
  return { ...parts, payload, signedAt: parts.integratedTime };
}
