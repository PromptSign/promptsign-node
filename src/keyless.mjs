// Offline verification of keyless (Sigstore-style) bundles per
// spec/05-keyless.md §4: stapled certificate chain to a trusted root (spec/07
// §3.1), SAN identity and Fulcio issuer from the leaf, and the Rekor signed
// entry timestamp. No network anywhere. Mirrors promptsign-core's keyless.rs.

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
import { loadRegistry, openWindow } from './trustroot.mjs';
import { b64decode, joinRaw } from './util.mjs';

// $PROMPTSIGN_TRUST_DIR, else $PROMPTSIGN_HOME/trust: where the built-in
// root's fulcio.pem and rekor.pub live.
export function trustDir() {
  return process.env.PROMPTSIGN_TRUST_DIR || joinRaw(promptsignHome(), 'trust');
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
  return { key, logId: sha256(der), spkiDer: Buffer.from(der), valid: openWindow() };
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

// The validity windows of spec/07 §4 at the log's integratedTime: the CA the
// chain ends at, under any of its entries, and the log key that witnessed it.
function checkWindows(a, log, t) {
  const ca = a.path[a.path.length - 1];
  if (!a.root.caValidAt(ca, t)) {
    throw new Error(
      `certificate authority "${ca.subject}" of trust root "${a.root.name}" was outside its validity window when the log witnessed the signature (integratedTime ${t})`,
    );
  }
  if (!log.valid.contains(t)) {
    throw new Error(
      `transparency log ${log.logId.slice(0, 16)}… of trust root "${a.root.name}" was outside its validity window at integratedTime ${t}`,
    );
  }
}

const str = (v) => (typeof v === 'string' ? v : undefined);

// Steps 1 to 6 of spec/05 §4 over parsed parts, against `roots`. The chain
// must end at a keyless root, the leaf must have signed the envelope, and one
// of that root's logs must have witnessed the entry while the leaf was valid.
export function verifyKeylessParts(chain, payloadType, payload, sigB64, tlog, roots) {
  const anchored = anchorChain(
    chain,
    roots.filter((r) => r.rekorLogs.length > 0),
  );
  const leaf = chain[0];

  // envelope signature (step 1)
  const sig = b64decode(sigB64);
  if (!sig) throw new Error('invalid base64 in signature');
  verifyLeafSignature(leaf, pae(payloadType, payload), sig);

  // SET over the canonical entry (step 3). The entry names the log that
  // witnessed it; pick that log's key from a root the chain ends at.
  let found = null;
  let windowError = null;
  for (const a of anchored) {
    const log = a.root.rekorLogs.find((l) => l.logId === tlog.logId);
    if (!log) continue;
    try {
      checkWindows(a, log, tlog.integratedTime);
      found = { anchor: a, log };
      break;
    } catch (e) {
      windowError ??= e;
    }
  }
  if (!found && windowError) throw windowError;
  if (!found) {
    const trusted = anchored.flatMap((a) => a.root.rekorLogs).map((l) => l.logId.slice(0, 16));
    throw new Error(
      `transparency logId ${tlog.logId} does not match any trusted log (trusted: ${trusted.join('…, ')}…)`,
    );
  }
  const canonical =
    `{"body":${JSON.stringify(tlog.bodyB64)},"integratedTime":${tlog.integratedTime},` +
    `"logID":${JSON.stringify(tlog.logId)},"logIndex":${tlog.logIndex}}`;
  const set = b64decode(tlog.setB64);
  if (!set) throw new Error('invalid base64 in signedEntryTimestamp');
  if (!isEcdsaSigDer(set)) throw new Error('malformed SET');
  let setOk = false;
  try {
    setOk = crypto.verify('sha256', Buffer.from(canonical), found.log.key, set);
  } catch {
    setOk = false;
  }
  if (!setOk) throw new Error('signed entry timestamp verification failed');

  // entry binding (step 4)
  const bodyRaw = b64decode(tlog.bodyB64);
  if (!bodyRaw) throw new Error('invalid base64 in body');
  let body;
  try {
    body = JSON.parse(bodyRaw.toString('utf8'));
  } catch (e) {
    throw new Error(`entry body: ${e.message}`);
  }
  if (body?.kind !== 'dsse') {
    const k = body?.kind;
    const shown = k === undefined ? 'undefined' : typeof k === 'string' ? k : JSON.stringify(k);
    throw new Error(`unexpected transparency entry kind: ${shown}`);
  }
  if ((str(body.spec?.payloadHash?.value) ?? '') !== sha256(payload)) {
    throw new Error('transparency entry payloadHash does not match envelope payload');
  }
  const entrySigs = Array.isArray(body.spec?.signatures) ? body.spec.signatures : [];
  if (!entrySigs.some((s) => str(s?.signature) === sigB64)) {
    throw new Error('transparency entry does not contain the envelope signature');
  }

  // cert validity at integration time (step 5)
  const t = tlog.integratedTime;
  if (t < leaf.notBefore || t > leaf.notAfter) {
    throw new Error(
      `log integration time ${t} outside certificate validity [${leaf.notBefore}, ${leaf.notAfter}]`,
    );
  }

  // identity extraction (step 6)
  const { identity, issuer } = leafIdentity(leaf);
  return {
    identity,
    issuer,
    leafKeyid: sha256(leaf.spkiDer),
    root: found.anchor.root.name,
    integratedTime: t,
  };
}

// Full offline keyless verification of a PromptSign bundle (spec/05 §4)
// against every keyless root in the registry. Returns the authenticated
// payload; manifest, integrity and policy are the caller's next steps.
export function verifyKeyless(bundle) {
  return verifyKeylessWith(bundle, keylessRoots());
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
    integratedTime: need('integratedTime', Number.isInteger),
    setB64: need('signedEntryTimestamp', isStr),
  };
  const parts = verifyKeylessParts(chain, payloadType, payload, sigB64, tlog, roots);

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
  return { ...parts, payload };
}
