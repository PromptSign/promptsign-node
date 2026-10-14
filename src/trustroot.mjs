// Multi-root trust (spec/07): the registry of named roots a verifier accepts.
//
// The built-in root "sigstore-public" is the pinned pair in the trust
// directory (fulcio.pem + rekor.pub), joined by the public trusted_root.json
// when the directory has one. Every other root is a document in
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
import { managedTrustDir } from './managed.mjs';
import { loadManagedPolicy } from './policy.mjs';
import { parseRekorLogs, rekorLogEd25519, rekorLogFromSpki, trustDir } from './keyless.mjs';
import { installedIn } from './trustbundle.mjs';
import { b64decode, formatIso8601, joinRaw, nowSecs, parseIso8601 } from './util.mjs';

export const DEFAULT_ROOT = 'sigstore-public';
export const TRUSTED_ROOT_MEDIA_TYPE = 'application/vnd.dev.sigstore.trustedroot+json;version=0.1';

// A validFor window, [start, end] in epoch seconds (spec/07 §4): closed at
// both ends, like Sigstore's TimeRange. A missing side is open, and a missing
// window is always valid.
export function window(start = null, end = null) {
  return {
    start,
    end,
    contains(t) {
      return !(this.start !== null && t < this.start) && !(this.end !== null && t > this.end);
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

function makeRoot(name, caCerts, caValid, rekorLogs, tsas = []) {
  if (caCerts.length === 0) throw new Error(`trust root "${name}": no CA certificates`);
  // The anchor is the self-signed certificate when the root carries one,
  // otherwise the last certificate given.
  const anchor = caCerts.find(isSelfSigned) ?? caCerts[caCerts.length - 1];
  return {
    name,
    caCerts,
    caValid,
    rekorLogs,
    // RFC 3161 timestamp authorities whose timestamps date signatures under
    // this root (spec/07 §1): [{ certs, valid, uri }].
    tsas,
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

// The certificates of a certChain object, in order.
function certsOf(chain) {
  return arr(chain?.certificates).map((c) => {
    if (typeof c?.rawBytes !== 'string') throw new Error('certificate without rawBytes');
    const der = b64decode(c.rawBytes);
    if (!der) throw new Error('invalid base64 in certificate rawBytes');
    try {
      return parseCertificate(der);
    } catch (e) {
      throw new Error(`certificate parse: ${e.message}`);
    }
  });
}

// A root from a Sigstore trusted_root.json document (spec/07 §1). Logs with a
// key other than ECDSA P-256 or Ed25519 are skipped, as is an Ed25519 log
// without a baseUrl (its id hashes the origin) and a log whose stated id is
// not the one its key and origin give.
export function rootFromTrustedRoot(name, doc) {
  const caCerts = [];
  const caValid = [];
  for (const ca of arr(doc?.certificateAuthorities)) {
    const w = windowFromJson(ca?.validFor);
    for (const cert of certsOf(ca?.certChain)) {
      caCerts.push(cert);
      caValid.push(w);
    }
  }
  const rekorLogs = [];
  for (const log of arr(doc?.tlogs)) {
    const details = log?.publicKey?.keyDetails;
    const baseUrl = typeof log?.baseUrl === 'string' && log.baseUrl !== '' ? log.baseUrl : null;
    const der = () => {
      if (typeof log.publicKey.rawBytes !== 'string') throw new Error('log key without rawBytes');
      const out = b64decode(log.publicKey.rawBytes);
      if (!out) throw new Error('invalid base64 in log key rawBytes');
      return out;
    };
    let rekor;
    if (typeof details === 'string' && details.startsWith('PKIX_ECDSA_P256')) {
      rekor = rekorLogFromSpki(der());
    } else if (details === 'PKIX_ED25519') {
      if (baseUrl === null) continue;
      rekor = rekorLogEd25519(der(), baseUrl);
    } else {
      continue;
    }
    const stated = log.logId?.keyId;
    if (typeof stated === 'string') {
      const id = b64decode(stated);
      if (!id) throw new Error('invalid base64');
      if (id.toString('hex') !== rekor.logId) continue;
    }
    rekor.valid = windowFromJson(log.publicKey.validFor);
    rekor.baseUrl = baseUrl;
    rekorLogs.push(rekor);
  }
  const tsas = [];
  for (const tsa of arr(doc?.timestampAuthorities)) {
    const certs = certsOf(tsa?.certChain);
    if (certs.length === 0) continue;
    tsas.push({
      certs,
      valid: windowFromJson(tsa?.validFor),
      uri: typeof tsa?.uri === 'string' ? tsa.uri : '',
    });
  }
  return makeRoot(name, caCerts, caValid, rekorLogs, tsas);
}

// The built-in root: the pinned pair joined with the public
// trusted_root.json. The document's CAs and logs come first, so its windows
// and base URLs apply; the pair adds what the document lacks.
function joined(name, doc, pinned) {
  const rekorLogs = [...doc.rekorLogs];
  for (const log of pinned.rekorLogs) {
    if (!rekorLogs.some((l) => l.logId === log.logId)) rekorLogs.push(log);
  }
  return makeRoot(
    name,
    [...doc.caCerts, ...pinned.caCerts],
    [...doc.caValid, ...pinned.caValid],
    rekorLogs,
    doc.tsas,
  );
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
      keyDetails: l.keyDetails(),
    };
    const w = windowToJson(l.valid);
    if (w) publicKey.validFor = w;
    const log = {
      hashAlgorithm: 'SHA2_256',
      publicKey,
      logId: { keyId: Buffer.from(l.logId, 'hex').toString('base64') },
    };
    if (l.baseUrl) log.baseUrl = l.baseUrl;
    return log;
  });
  const timestampAuthorities = root.tsas.map((t) => {
    const out = {
      subject: { commonName: t.certs[t.certs.length - 1]?.subject ?? '' },
      certChain: { certificates: t.certs.map((c) => ({ rawBytes: c.der.toString('base64') })) },
    };
    if (t.uri !== '') out.uri = t.uri;
    const w = windowToJson(t.valid);
    if (w) out.validFor = w;
    return out;
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
    timestampAuthorities,
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

// The built-in root from the trust directory: the pinned pair (fulcio.pem +
// rekor.pub), the public trusted_root.json, or both joined. The document is
// what carries Rekor v2 logs and timestamp authorities.
export function loadPinned(dir) {
  const fulcio = joinRaw(dir, 'fulcio.pem');
  const rekor = joinRaw(dir, 'rekor.pub');
  const docPath = joinRaw(dir, 'trusted_root.json');
  let pinned = null;
  if (fs.existsSync(fulcio) && fs.existsSync(rekor)) {
    const pem = fs.readFileSync(fulcio);
    const rekorPem = fs.readFileSync(rekor, 'utf8');
    try {
      pinned = rootFromPem(DEFAULT_ROOT, pem, rekorPem);
    } catch (e) {
      throw new Error(`${dir}: ${e.message}`);
    }
  }
  let doc = null;
  if (fs.existsSync(docPath)) {
    try {
      doc = rootFromTrustedRoot(DEFAULT_ROOT, JSON.parse(fs.readFileSync(docPath, 'utf8')));
    } catch (e) {
      throw new Error(`${docPath}: ${e.message}`);
    }
  }
  if (doc && pinned) return joined(DEFAULT_ROOT, doc, pinned);
  return doc ?? pinned;
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

// True when `dir` holds the built-in root: the pinned pair, the public
// trusted_root.json, or both.
function hasBuiltin(dir) {
  return (
    fs.existsSync(joinRaw(dir, 'trusted_root.json')) ||
    (fs.existsSync(joinRaw(dir, 'fulcio.pem')) && fs.existsSync(joinRaw(dir, 'rekor.pub')))
  );
}

// The directory the built-in root comes from: the managed trust directory
// when it holds one (spec/07 §2.4), else the trust directory.
export function builtinRootDir() {
  const managed = managedTrustDir();
  return hasBuiltin(managed) ? managed : trustDir();
}

// The built-in root sigstore-public, or null when this machine has none.
export function loadBuiltin() {
  const managed = managedTrustDir();
  if (hasBuiltin(managed)) {
    const root = loadPinned(managed);
    return root && { ...root, managed: true };
  }
  return loadPinned(trustDir());
}

const isManaged = (root) => ({ ...root, managed: true });

// Every root this verifier accepts (spec/07 §2): the built-in root, the
// managed named roots and trust bundles, then the user's own, unless the
// managed policy sets user_roots: false. A user root or bundle with the name
// of a managed one is left out, so a policy rule that names a managed root
// can only match that root. Returns { roots, bundles, ignored }: the trust
// bundles the roots came from, and the user's roots and bundles left out,
// with the reason.
export function loadFullRegistry(now) {
  const builtin = loadBuiltin();
  const pub = builtin ? [builtin] : [];
  const mdir = managedTrustDir();
  const managedNamed = loadNamedIn(rootsDir(mdir)).map(isManaged);
  const bundles = installedIn(mdir, pub, now).map((b) => ({
    ...b,
    managed: true,
    bundle: { ...b.bundle, roots: b.bundle.roots.map(isManaged) },
  }));
  const taken = [...managedNamed.map((r) => r.name), ...bundles.map((b) => b.bundle.name)];
  const roots = [...pub, ...managedNamed];
  const ignored = [];
  for (const b of bundles) roots.push(...b.bundle.roots);

  const udir = userTrustDir();
  const userRoots = loadManagedPolicy()?.policy.user_roots !== false;
  if (!userRoots) {
    const hasAny = (d) => {
      try {
        return fs.readdirSync(d).length > 0;
      } catch {
        return false;
      }
    };
    if (hasAny(rootsDir(udir)) || hasAny(joinRaw(udir, 'bundles'))) {
      ignored.push(`${udir}: ignored, the managed policy sets user_roots to false`);
    }
    return { roots, bundles, ignored };
  }
  for (const r of loadNamedIn(rootsDir(udir))) {
    if (taken.includes(r.name)) {
      ignored.push(
        `trust root "${r.name}" in ${udir}: ignored, a managed root or bundle has that name`,
      );
      continue;
    }
    roots.push(r);
  }
  for (const b of installedIn(udir, pub, now)) {
    if (taken.includes(b.bundle.name)) {
      ignored.push(
        `trust bundle "${b.bundle.name}" in ${udir}: ignored, a managed root or bundle has that name`,
      );
      continue;
    }
    roots.push(...b.bundle.roots);
    bundles.push({ ...b, managed: false });
  }
  return { roots, bundles, ignored };
}

// Every root this verifier accepts: loadFullRegistry at the current time. A
// root file that does not parse, or a stored bundle that does not verify, is
// an error, not a silent skip.
export function loadRegistry() {
  return loadFullRegistry(nowSecs()).roots;
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
