// Multi-root trust (spec/07): the registry of named roots a verifier accepts.
//
// The built-in root "sigstore-public" is the pinned pair in the trust
// directory (fulcio.pem + rekor.pub). Every other root is a document in
// Sigstore's trusted_root.json shape under $PROMPTSIGN_HOME/trust/roots/
// <name>.json, or a root of an installed trust bundle, named <bundle>/<root>.
// A root with transparency logs verifies keyless signatures; one with
// certificate authorities only is a certificate root. Mirrors trustroot.rs,
// including the on-disk layout, so Rust and Node can share PROMPTSIGN_HOME.

import fs from 'node:fs';
import { sha256 } from './canonicalize.mjs';
import { isSelfSigned } from './chain.mjs';
import { parseCertificate, pemBodies } from './der.mjs';
import { promptsignHome } from './keys.mjs';
import { parseRekorLogs, rekorLogFromSpki, trustDir } from './keyless.mjs';
import { installedIn } from './trustbundle.mjs';
import { b64decode, formatIso8601, joinRaw, nowSecs, parseIso8601 } from './util.mjs';

export const DEFAULT_ROOT = 'sigstore-public';
export const TRUSTED_ROOT_MEDIA_TYPE = 'application/vnd.dev.sigstore.trustedroot+json;version=0.1';

// A validFor window, [start, end) in epoch seconds (spec/07 §4). A missing
// side is open, and a missing window is always valid.
export function window(start = null, end = null) {
  return {
    start,
    end,
    contains(t) {
      return !(this.start !== null && t < this.start) && !(this.end !== null && t >= this.end);
    },
  };
}

export function openWindow() {
  return window();
}

const sameWindow = (a, b) => a.start === b.start && a.end === b.end;

export function windowFromJson(v) {
  if (v === null || v === undefined || typeof v !== 'object' || Array.isArray(v)) {
    return openWindow();
  }
  const side = (key) => {
    const t = v[key];
    if (t === undefined || t === null) return null;
    const secs = parseIso8601(t);
    if (secs === null) {
      throw new Error(`validFor.${key} is not an RFC 3339 time: ${JSON.stringify(t)}`);
    }
    return secs;
  };
  return window(side('start'), side('end'));
}

function windowToJson(w) {
  if (w.start === null && w.end === null) return null;
  const out = {};
  if (w.start !== null) out.start = formatIso8601(w.start);
  if (w.end !== null) out.end = formatIso8601(w.end);
  return out;
}

function makeRoot(name, caCerts, caValid, rekorLogs) {
  if (caCerts.length === 0) throw new Error(`trust root "${name}": no CA certificates`);
  // The anchor is the self-signed certificate when the root carries one,
  // otherwise the last certificate given.
  const anchor = caCerts.find(isSelfSigned) ?? caCerts[caCerts.length - 1];
  return {
    name,
    caCerts,
    caValid,
    rekorLogs,
    fingerprint: sha256(anchor.der),
    subject: anchor.subject,
    // For a root from a trust bundle, that bundle's expiry (spec/07 §5.6).
    expires: null,
    isCaOnly() {
      return this.rekorLogs.length === 0;
    },
    // Whether `cert`, a CA of this root, was valid at `t` under any of the
    // CA entries that list it.
    caValidAt(cert, t) {
      return this.caCerts.some((c, i) => c.der.equals(cert.der) && this.caValid[i].contains(t));
    },
  };
}

function pemCertificates(pem, what) {
  try {
    return pemBodies(pem.toString('utf8'), 'CERTIFICATE').map(parseCertificate);
  } catch (e) {
    throw new Error(`${what}: ${e.message}`);
  }
}

// A keyless root from the pinned PEM pair (fulcio.pem, rekor.pub).
export function rootFromPem(name, fulcioPem, rekorPem) {
  const caCerts = pemCertificates(fulcioPem, 'CA certificates');
  return makeRoot(
    name,
    caCerts,
    caCerts.map(() => openWindow()),
    parseRekorLogs(rekorPem),
  );
}

// A certificate-mode root from one or more PEM CA certificates.
export function rootCaOnly(name, caPem) {
  const caCerts = pemCertificates(caPem, 'CA certificate');
  return makeRoot(
    name,
    caCerts,
    caCerts.map(() => openWindow()),
    [],
  );
}

const arr = (v) => (Array.isArray(v) ? v : []);

// A root from a Sigstore trusted_root.json document (spec/07 §1). Logs whose
// key is not ECDSA P-256 are skipped, and so is a log whose stated id is not
// its key's.
export function rootFromTrustedRoot(name, doc) {
  const caCerts = [];
  const caValid = [];
  for (const ca of arr(doc?.certificateAuthorities)) {
    const w = windowFromJson(ca?.validFor);
    for (const c of arr(ca?.certChain?.certificates)) {
      if (typeof c?.rawBytes !== 'string') throw new Error('certificate without rawBytes');
      const der = b64decode(c.rawBytes);
      if (!der) throw new Error('invalid base64 in certificate rawBytes');
      try {
        caCerts.push(parseCertificate(der));
      } catch (e) {
        throw new Error(`certificate parse: ${e.message}`);
      }
      caValid.push(w);
    }
  }
  const rekorLogs = [];
  for (const log of arr(doc?.tlogs)) {
    const details = log?.publicKey?.keyDetails;
    if (typeof details !== 'string' || !details.startsWith('PKIX_ECDSA_P256')) continue;
    if (typeof log.publicKey.rawBytes !== 'string') throw new Error('log key without rawBytes');
    const der = b64decode(log.publicKey.rawBytes);
    if (!der) throw new Error('invalid base64 in log key rawBytes');
    const rekor = rekorLogFromSpki(der);
    const stated = log.logId?.keyId;
    if (typeof stated === 'string') {
      const id = b64decode(stated);
      if (!id) throw new Error('invalid base64');
      if (id.toString('hex') !== rekor.logId) continue;
    }
    rekor.valid = windowFromJson(log.publicKey.validFor);
    rekorLogs.push(rekor);
  }
  return makeRoot(name, caCerts, caValid, rekorLogs);
}

// Recursively sort object keys: the Rust side writes serde_json Values,
// whose maps are ordered by key.
export function sortKeys(v) {
  if (Array.isArray(v)) return v.map(sortKeys);
  if (v && typeof v === 'object') {
    return Object.fromEntries(
      Object.keys(v)
        .sort()
        .map((k) => [k, sortKeys(v[k])]),
    );
  }
  return v;
}

// A root as a trusted_root.json document. Consecutive certificates with the
// same window share one CA entry.
export function rootToTrustedRoot(root) {
  const tlogs = root.rekorLogs.map((l) => {
    const publicKey = {
      rawBytes: l.spkiDer.toString('base64'),
      keyDetails: 'PKIX_ECDSA_P256_SHA_256',
    };
    const w = windowToJson(l.valid);
    if (w) publicKey.validFor = w;
    return {
      hashAlgorithm: 'SHA2_256',
      publicKey,
      logId: { keyId: Buffer.from(l.logId, 'hex').toString('base64') },
    };
  });
  const groups = [];
  root.caCerts.forEach((c, i) => {
    const w = root.caValid[i];
    const raw = { rawBytes: c.der.toString('base64') };
    const last = groups[groups.length - 1];
    if (last && sameWindow(last.w, w)) last.certificates.push(raw);
    else groups.push({ w, certificates: [raw] });
  });
  const certificateAuthorities = groups.map(({ w, certificates }) => {
    const ca = { subject: { commonName: root.subject }, certChain: { certificates } };
    const vf = windowToJson(w);
    if (vf) ca.validFor = vf;
    return ca;
  });
  return sortKeys({
    mediaType: TRUSTED_ROOT_MEDIA_TYPE,
    tlogs,
    certificateAuthorities,
    ctlogs: [],
    timestampAuthorities: [],
  });
}

export function rootsDir(dir) {
  return joinRaw(dir, 'roots');
}

export function checkName(name) {
  const ok =
    name.length > 0 && name.length <= 64 && !name.startsWith('.') && /^[a-z0-9._-]*$/.test(name);
  if (!ok) {
    throw new Error(
      `invalid trust root name "${name}": use lower-case letters, digits, '-', '_' or '.'`,
    );
  }
  if (name === DEFAULT_ROOT) throw new Error(`"${DEFAULT_ROOT}" is the built-in root`);
}

// $PROMPTSIGN_HOME/trust: named roots and bundles. Unlike the pinned public
// root, this never follows PROMPTSIGN_TRUST_DIR.
export function userTrustDir() {
  return joinRaw(promptsignHome(), 'trust');
}

const isDir = (p) => {
  try {
    return fs.statSync(p).isDirectory();
  } catch {
    return false;
  }
};

export function loadPinned(dir) {
  const fulcio = joinRaw(dir, 'fulcio.pem');
  const rekor = joinRaw(dir, 'rekor.pub');
  if (!fs.existsSync(fulcio) || !fs.existsSync(rekor)) return null;
  const pem = fs.readFileSync(fulcio);
  const rekorPem = fs.readFileSync(rekor, 'utf8');
  try {
    return rootFromPem(DEFAULT_ROOT, pem, rekorPem);
  } catch (e) {
    throw new Error(`${dir}: ${e.message}`);
  }
}

export function loadNamedIn(rdir) {
  if (!isDir(rdir)) return [];
  const files = fs
    .readdirSync(rdir)
    .filter((f) => f.length > 5 && f.endsWith('.json'))
    .sort();
  return files.map((f) => {
    const p = joinRaw(rdir, f);
    const name = f.slice(0, -5);
    try {
      checkName(name);
      return rootFromTrustedRoot(name, JSON.parse(fs.readFileSync(p, 'utf8')));
    } catch (e) {
      throw new Error(`${p}: ${e.message}`);
    }
  });
}

function registry(dir, pinned) {
  const bundles = installedIn(dir, pinned, nowSecs());
  const roots = [...pinned, ...loadNamedIn(rootsDir(dir))];
  for (const installed of bundles) roots.push(...installed.bundle.roots);
  return roots;
}

// Every root the user trusts (spec/07 §2): the pinned public root from the
// trust directory, the user's named roots, then the roots of each installed
// trust bundle. A root file that does not parse, or a stored bundle that
// does not verify, is an error, not a silent skip.
export function loadRegistry() {
  const pinned = loadPinned(trustDir());
  return registry(userTrustDir(), pinned ? [pinned] : []);
}

export function loadRegistryFrom(dir) {
  const pinned = loadPinned(dir);
  return registry(dir, pinned ? [pinned] : []);
}

function storeRoot(dir, root) {
  const p = joinRaw(rootsDir(dir), `${root.name}.json`);
  if (fs.existsSync(p)) throw new Error(`trust root "${root.name}" already exists`);
  const same = loadRegistryFrom(dir).find((r) => r.fingerprint === root.fingerprint);
  if (same) throw new Error(`this root is already trusted as "${same.name}"`);
  fs.mkdirSync(rootsDir(dir), { recursive: true });
  fs.writeFileSync(p, JSON.stringify(rootToTrustedRoot(root), null, 2) + '\n');
  return root;
}

// Add a certificate-mode root from PEM CA certificates. Refuses a name in
// use and a root already trusted under another name.
export function addCaRoot(dir, name, caPem) {
  checkName(name);
  return storeRoot(dir, rootCaOnly(name, caPem));
}

// Add a root from a trusted_root.json document (a private Sigstore
// deployment, or a CA published in that shape).
export function addTrustedRoot(dir, name, doc) {
  checkName(name);
  return storeRoot(dir, rootFromTrustedRoot(name, doc));
}

export function removeRoot(dir, name) {
  checkName(name);
  const p = joinRaw(rootsDir(dir), `${name}.json`);
  if (!fs.existsSync(p)) throw new Error(`no trust root named "${name}"`);
  fs.rmSync(p);
}
