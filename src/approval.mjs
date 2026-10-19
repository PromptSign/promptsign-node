// Approvals (spec/09): someone other than the author signs an in-toto
// Statement over an artifact's content digest. This module computes the
// content listing, finds approval files, verifies them offline and keeps the
// ones that cover the artifact. Mirrors promptsign-core's approval.rs for
// keyless approvals; a certificate-mode approval does not count here.

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { parseCertificate } from './der.mjs';
import { promptsignHome } from './keys.mjs';
import { b64List, keylessRoots, verifyKeylessParts, verifyKeylessWith } from './keyless.mjs';
import { managedDir } from './managed.mjs';
import { buildManifest } from './manifest.mjs';
import { b64decode, joinRaw } from './util.mjs';

export const STATEMENT_TYPE = 'https://in-toto.io/Statement/v1';
export const APPROVAL_PREDICATE = 'https://promptsign.dev/approval/v1';
export const IN_TOTO_PAYLOAD_TYPE = 'application/vnd.in-toto+json';
const APPROVALS_DIR = 'approvals';

// The content listing of a manifest's files (spec/09 §1): one
// "<sha256>  <path>" line per file, sorted by path bytes, and its digest.
export function listingOf(files) {
  const text = files
    .map((f) => [f.path, f.sha256])
    .sort(([a], [b]) => Buffer.compare(Buffer.from(a), Buffer.from(b)))
    .map(([p, h]) => `${h}  ${p}\n`)
    .join('');
  return { text, digest: crypto.createHash('sha256').update(text, 'utf8').digest('hex') };
}

// The content listing of the artifact on disk, as a signer would build its
// manifest. Throws on a tree a signer refuses, such as one with a link.
export function listingFor(target) {
  const abs = path.resolve(target);
  const manifest = fs.statSync(abs).isDirectory()
    ? buildManifest({ root: abs })
    : buildManifest({ root: path.dirname(abs), singleFile: abs });
  return listingOf(manifest.files);
}

const str = (v) => (typeof v === 'string' ? v : undefined);

// The keyless parts of a Sigstore bundle (v0.1 to v0.3): its chain, DSSE
// envelope, first log entry and timestamps.
function sigstoreParts(bundle) {
  const vm = bundle.verificationMaterial ?? {};
  const raw = vm.certificate?.rawBytes
    ? [vm.certificate.rawBytes]
    : (vm.x509CertificateChain?.certificates ?? []).map((c) => c?.rawBytes);
  const chain = b64List(raw, 'certificate').map((der) => parseCertificate(der));
  if (chain.length === 0) throw new Error('Sigstore bundle has no certificate');
  const e = vm.tlogEntries?.[0];
  if (e === undefined) {
    throw new Error('certificate-mode approvals need the promptsign CLI to verify');
  }
  const d = bundle.dsseEnvelope;
  const payloadType = str(d?.payloadType);
  const payload = b64decode(str(d?.payload) ?? '');
  const sigB64 = str(d?.signatures?.[0]?.sig);
  const sig = sigB64 === undefined ? null : b64decode(sigB64);
  if (payloadType === undefined || !payload || !sig) {
    throw new Error('Sigstore bundle has no DSSE envelope');
  }
  const keyId = b64decode(str(e.logId?.keyId) ?? '');
  const logIndex = Number(e.logIndex);
  if (!keyId || !Number.isSafeInteger(logIndex))
    throw new Error('tlog entry has no logId or logIndex');
  let proof;
  const promise = str(e.inclusionPromise?.signedEntryTimestamp);
  if (promise !== undefined) {
    const integratedTime = Number(e.integratedTime);
    if (!Number.isSafeInteger(integratedTime)) throw new Error('tlog entry has no integratedTime');
    proof = { integratedTime, setB64: promise };
  } else {
    const p = e.inclusionProof;
    const rootHash = b64decode(str(p?.rootHash) ?? '');
    const checkpoint = str(p?.checkpoint?.envelope);
    if (!rootHash || checkpoint === undefined || !/^\d+$/.test(String(p?.treeSize))) {
      throw new Error('tlog entry has neither an inclusion promise nor an inclusion proof');
    }
    proof = {
      treeSize: BigInt(p.treeSize),
      rootHash,
      hashes: b64List(p.hashes, 'inclusionProof.hashes'),
      checkpoint,
    };
  }
  return {
    chain,
    env: { payloadType, payload, sig, sigB64 },
    tlog: {
      bodyB64: str(e.canonicalizedBody) ?? '',
      logId: keyId.toString('hex'),
      logIndex,
      proof,
    },
    timestamps: b64List(
      (vm.timestampVerificationData?.rfc3161Timestamps ?? []).map((t) => t?.signedTimestamp),
      'rfc3161Timestamps',
    ),
  };
}

// Verify one approval bundle offline (spec/09 §2, §3). Returns
// { identity, issuer, root, signedAt, payloadDigest, logIndex } when it
// covers `digest`, null when it verifies but approves other content, and
// throws when it does not verify.
export function verifyApproval(bundle, digest, roots = keylessRoots()) {
  let signer;
  let payloadType;
  let payload;
  let logIndex;
  if (String(bundle?.mediaType ?? '').startsWith('application/vnd.dev.sigstore.bundle')) {
    const parts = sigstoreParts(bundle);
    ({ payloadType, payload } = parts.env);
    if (payloadType !== IN_TOTO_PAYLOAD_TYPE) {
      throw new Error(`payloadType "${payloadType}" is not an in-toto statement`);
    }
    signer = verifyKeylessParts(parts.chain, parts.env, parts.tlog, parts.timestamps, roots);
    logIndex = parts.tlog.logIndex;
  } else {
    payloadType = bundle?.envelope?.payloadType;
    if (payloadType !== IN_TOTO_PAYLOAD_TYPE) {
      throw new Error(`payloadType "${payloadType ?? ''}" is not an in-toto statement`);
    }
    const kv = verifyKeylessWith(bundle, roots);
    signer = kv;
    payload = kv.payload;
    logIndex = bundle.transparency?.logIndex;
  }

  let doc;
  try {
    doc = JSON.parse(payload.toString('utf8'));
  } catch (e) {
    throw new Error(`statement: ${e.message}`);
  }
  if (doc?._type !== STATEMENT_TYPE) throw new Error('not an in-toto Statement v1');
  if (doc.predicateType !== APPROVAL_PREDICATE) {
    throw new Error(`predicateType ${JSON.stringify(doc.predicateType)} is not an approval`);
  }
  if (doc.predicate === null || typeof doc.predicate !== 'object' || Array.isArray(doc.predicate)) {
    throw new Error('predicate is not an object');
  }
  const covers = (Array.isArray(doc.subject) ? doc.subject : []).some(
    (s) => s?.digest?.sha256 === digest,
  );
  if (!covers) return null;
  return {
    identity: signer.identity,
    issuer: signer.issuer,
    root: signer.root,
    signedAt: signer.integratedTime,
    payloadDigest: `sha256:${crypto.createHash('sha256').update(payload).digest('hex')}`,
    logIndex,
  };
}

// The .promptsign/approvals/ directory that travels with the artifact.
export function localDir(target, isDir) {
  return path.join(isDir ? target : path.dirname(target), '.promptsign', APPROVALS_DIR);
}

// Every approval file a verifier reads for an artifact (spec/09 §3), each
// directory's files sorted by name.
export function approvalFiles(target, isDir, digest) {
  const dirs = [
    localDir(target, isDir),
    joinRaw(managedDir(), APPROVALS_DIR, digest),
    joinRaw(promptsignHome(), APPROVALS_DIR, digest),
  ];
  const files = [];
  for (const dir of dirs) {
    let names;
    try {
      names = fs.readdirSync(dir);
    } catch {
      continue;
    }
    for (const n of names.filter((n) => n.endsWith('.json')).sort()) {
      const p = path.join(dir, n);
      if (fs.statSync(p).isFile()) files.push(p);
    }
  }
  return files;
}

// The approvals among `files` that verify and cover `digest`, once each, and
// an info finding for each file that does not verify. It loads the registry
// when it has a file to check.
export function collect(files, digest, roots = null) {
  const approvals = [];
  const findings = [];
  for (const file of files) {
    let a;
    try {
      roots ??= keylessRoots();
      a = verifyApproval(JSON.parse(fs.readFileSync(file, 'utf8')), digest, roots);
    } catch (e) {
      findings.push({ level: 'info', message: `approval ${file} not counted: ${e.message}` });
      continue;
    }
    if (
      a &&
      !approvals.some(
        (b) =>
          b.identity === a.identity && b.issuer === a.issuer && b.payloadDigest === a.payloadDigest,
      )
    ) {
      approvals.push(a);
    }
  }
  return { approvals, findings };
}
