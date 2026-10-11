// Trust bundles (spec/07 §5): an organization's roots in one signed,
// versioned document. A bundle is an ordinary file with an ordinary keyless
// sidecar signature, so verifying one needs nothing beyond the verifier.
//
// Installing trusts the bundle's own signers, which is why the CLI asks the
// user first. Every later version must be signed by a signer the installed
// version names, carry a higher version number, and not have expired.
// Mirrors trustbundle.rs, storage layout included.

import fs from 'node:fs';
import { PAYLOAD_TYPE } from './bundle.mjs';
import { sha256 } from './canonicalize.mjs';
import { trustDir, verifyKeylessWith } from './keyless.mjs';
import { globMatch } from './policy.mjs';
import {
  DEFAULT_ROOT,
  checkName,
  loadNamedIn,
  loadPinned,
  rootFromTrustedRoot,
  rootsDir,
  userTrustDir,
} from './trustroot.mjs';
import { formatIso8601, joinRaw, parseIso8601 } from './util.mjs';

export const TRUST_BUNDLE_SCHEMA = 'promptsign/trust-bundle/v1';
export const BUNDLE_FILE = 'trust-bundle.json';
export const SIDECAR_FILE = 'trust-bundle.json.psig.json';
const SOURCE_FILE = 'source.json';
// How far in the future `issued` may be before a bundle is refused.
const MAX_CLOCK_SKEW = 300;

const isObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

// Parse and check a bundle document (spec/07 §5.1) to be installed as `name`.
// Roots are named <name>/<root>; signers' roots are resolved the same way.
export function parseTrustBundle(name, bytes) {
  checkName(name);
  let v;
  try {
    v = JSON.parse(Buffer.from(bytes).toString('utf8'));
  } catch (e) {
    throw new Error(`trust bundle: ${e.message}`);
  }
  const get = (key) => (isObject(v) ? v[key] : undefined);
  if (get('schema') !== TRUST_BUNDLE_SCHEMA) {
    throw new Error(
      `not a trust bundle: schema is ${JSON.stringify(get('schema') ?? null)}, expected ${TRUST_BUNDLE_SCHEMA}`,
    );
  }
  const version = get('version');
  if (!Number.isSafeInteger(version) || version < 1) {
    throw new Error('trust bundle version must be an integer of at least 1');
  }
  const time = (key) => {
    const t = parseIso8601(get(key));
    if (t === null) throw new Error(`trust bundle ${key} is not an RFC 3339 time`);
    return t;
  };
  const issued = time('issued');
  const expires = time('expires');
  if (expires <= issued) throw new Error('trust bundle expires before it is issued');

  const docs = get('roots');
  if (!isObject(docs) || Object.keys(docs).length === 0) {
    throw new Error('trust bundle lists no roots');
  }
  const roots = [];
  for (const key of Object.keys(docs).sort()) {
    try {
      checkName(key);
    } catch (e) {
      throw new Error(`trust bundle root: ${e.message}`);
    }
    let root;
    try {
      root = rootFromTrustedRoot(`${name}/${key}`, docs[key]);
    } catch (e) {
      throw new Error(`trust bundle root "${key}": ${e.message}`);
    }
    const twin = roots.find((r) => r.fingerprint === root.fingerprint);
    if (twin) {
      throw new Error(`trust bundle lists the same root twice: "${key}" and "${twin.name}"`);
    }
    root.expires = expires;
    roots.push(root);
  }

  const list = get('signers');
  if (!Array.isArray(list) || list.length === 0) throw new Error('trust bundle lists no signers');
  const signers = list.map((s) => {
    const field = (key) => {
      const x = isObject(s) ? s[key] : undefined;
      if (typeof x !== 'string' || x === '') throw new Error(`trust bundle signer has no ${key}`);
      return x;
    };
    const root = field('root');
    let resolved;
    if (root === DEFAULT_ROOT) resolved = root;
    else if (Object.hasOwn(docs, root)) resolved = `${name}/${root}`;
    else {
      throw new Error(
        `trust bundle signer root "${root}" is neither ${DEFAULT_ROOT} nor one of the bundle's roots`,
      );
    }
    return { identity: field('identity'), issuer: field('issuer'), root: resolved };
  });

  const suggested = get('name');
  return {
    name,
    suggestedName: typeof suggested === 'string' ? suggested : '',
    version,
    issued,
    expires,
    roots,
    signers,
  };
}

// Steps 1 and 2 of spec/07 §5.2: the sidecar is a valid keyless signature
// over exactly these bytes, by one of `accept`'s signers, chained to that
// signer's root (the built-in root or one of `accept`'s).
function verifySigned(bytes, sidecar, accept, pub) {
  if (sidecar?.envelope?.payloadType !== PAYLOAD_TYPE) {
    throw new Error('trust bundle signature is not a PromptSign signature');
  }
  let kv;
  try {
    kv = verifyKeylessWith(sidecar, [...pub, ...accept.roots]);
  } catch (e) {
    throw new Error(`trust bundle signature: ${e.message}`);
  }
  let manifest;
  try {
    manifest = JSON.parse(kv.payload.toString('utf8'));
  } catch (e) {
    throw new Error(`trust bundle signature: manifest: ${e.message}`);
  }
  const files = Array.isArray(manifest?.files) ? manifest.files : [];
  const covers =
    manifest?.scope === 'file' && files.length === 1 && files[0]?.sha256 === sha256(bytes);
  if (!covers) {
    throw new Error(
      `trust bundle signature: modified: ${BUNDLE_FILE} (the signature covers other bytes)`,
    );
  }
  const seen = { identity: kv.identity, issuer: kv.issuer, root: kv.root };
  const listed = accept.signers.some(
    (s) => globMatch(s.identity, seen.identity) && s.issuer === seen.issuer && s.root === seen.root,
  );
  if (!listed) {
    throw new Error(
      `"${seen.identity}" (issuer ${seen.issuer}, root ${seen.root}) is not a signer of trust bundle "${accept.name}" version ${accept.version}`,
    );
  }
  return seen;
}

function bundlesDir(dir) {
  return joinRaw(dir, 'bundles');
}

const isDir = (p) => {
  try {
    return fs.statSync(p).isDirectory();
  } catch {
    return false;
  }
};

function readSource(bdir) {
  try {
    const url = JSON.parse(fs.readFileSync(joinRaw(bdir, SOURCE_FILE), 'utf8'))?.url;
    return typeof url === 'string' ? url : null;
  } catch {
    return null;
  }
}

// The installed bundle `name` and its bytes, re-verified against its own
// signers (spec/07 §5.5). null when no such bundle is installed.
function loadInstalled(dir, name, pub) {
  const bdir = joinRaw(bundlesDir(dir), name);
  if (!isDir(bdir)) return null;
  try {
    const bytes = fs.readFileSync(joinRaw(bdir, BUNDLE_FILE));
    const sidecar = JSON.parse(fs.readFileSync(joinRaw(bdir, SIDECAR_FILE), 'utf8'));
    const bundle = parseTrustBundle(name, bytes);
    verifySigned(bytes, sidecar, bundle, pub);
    return { installed: { bundle, source: readSource(bdir), stale: false }, bytes };
  } catch (e) {
    throw new Error(`stored trust bundle "${name}": ${e.message}`);
  }
}

// Every installed bundle in `dir`, re-verified, with its staleness at `now`.
export function installedIn(dir, pub, now) {
  let names;
  try {
    names = fs
      .readdirSync(bundlesDir(dir), { withFileTypes: true })
      .filter((e) => isDir(joinRaw(bundlesDir(dir), e.name)) && !e.name.startsWith('.'))
      .map((e) => e.name)
      .sort();
  } catch {
    return [];
  }
  const out = [];
  for (const name of names) {
    const found = loadInstalled(dir, name, pub);
    if (found) {
      found.installed.stale = found.installed.bundle.expires <= now;
      out.push(found.installed);
    }
  }
  return out;
}

// What installing a candidate would do, for the user to confirm:
// { bundle, signer, update, unchanged }.
function checkIn(dir, pub, named, name, bytes, sidecar, now) {
  const candidate = parseTrustBundle(name, bytes);
  const current = loadInstalled(dir, name, pub);
  if (current && current.bytes.equals(Buffer.from(bytes))) {
    const signer = verifySigned(bytes, sidecar, current.installed.bundle, pub);
    return { bundle: candidate, signer, update: true, unchanged: true };
  }
  const accept = current ? current.installed.bundle : candidate;
  const signer = verifySigned(bytes, sidecar, accept, pub);
  if (current && candidate.version <= current.installed.bundle.version) {
    throw new Error(
      `trust bundle "${name}" version ${candidate.version} is not newer than the installed version ${current.installed.bundle.version}: refusing a rollback`,
    );
  }
  if (candidate.expires <= now) {
    throw new Error(`trust bundle "${name}" expired at ${formatIso8601(candidate.expires)}`);
  }
  if (candidate.issued > now + MAX_CLOCK_SKEW) {
    throw new Error(
      `trust bundle "${name}" is issued in the future (${formatIso8601(candidate.issued)})`,
    );
  }

  // A root may be trusted under one name only, so policy names stay
  // unambiguous. This bundle's own installed roots do not count.
  const others = [...pub, ...named];
  for (const other of installedIn(dir, pub, now)) {
    if (other.bundle.name !== name) others.push(...other.bundle.roots);
  }
  for (const r of candidate.roots) {
    const o = others.find((x) => x.fingerprint === r.fingerprint);
    if (o) {
      throw new Error(
        `root "${r.name}" of trust bundle "${name}" is already trusted as "${o.name}"`,
      );
    }
  }
  return { bundle: candidate, signer, update: current !== null, unchanged: false };
}

const pinnedList = (dir) => {
  const p = loadPinned(dir);
  return p ? [p] : [];
};

// Everything §5.2 checks before installing `bytes` as bundle `name` in the
// trust directory `dir`, whose pinned pair is the built-in root. Writes
// nothing.
export function checkTrustBundle(dir, name, bytes, sidecar, now) {
  return checkIn(dir, pinnedList(dir), loadNamedIn(rootsDir(dir)), name, bytes, sidecar, now);
}

// checkTrustBundle against the user's trust directory and built-in root.
export function checkUserTrustBundle(name, bytes, sidecar, now) {
  const dir = userTrustDir();
  return checkIn(
    dir,
    pinnedList(trustDir()),
    loadNamedIn(rootsDir(dir)),
    name,
    bytes,
    sidecar,
    now,
  );
}

export function installedBundles(dir, now) {
  return installedIn(dir, pinnedList(dir), now);
}

export function installedUserBundles(now) {
  return installedIn(userTrustDir(), pinnedList(trustDir()), now);
}

// Write a bundle that checkTrustBundle accepted, replacing an installed
// version in one step. A null source keeps the installed one.
export function storeTrustBundle(dir, name, bytes, sidecar, source) {
  checkName(name);
  const parent = bundlesDir(dir);
  const target = joinRaw(parent, name);
  const staging = joinRaw(parent, `.${name}.new-${process.pid}`);
  const retired = joinRaw(parent, `.${name}.old-${process.pid}`);
  const url = source ?? readSource(target);

  fs.rmSync(staging, { recursive: true, force: true });
  fs.mkdirSync(staging, { recursive: true });
  fs.writeFileSync(joinRaw(staging, BUNDLE_FILE), bytes);
  fs.writeFileSync(joinRaw(staging, SIDECAR_FILE), sidecar);
  if (url !== null) {
    fs.writeFileSync(joinRaw(staging, SOURCE_FILE), JSON.stringify({ url }, null, 2) + '\n');
  }
  if (fs.existsSync(target)) {
    fs.rmSync(retired, { recursive: true, force: true });
    fs.renameSync(target, retired);
  }
  fs.renameSync(staging, target);
  fs.rmSync(retired, { recursive: true, force: true });
}

// Remove the installed bundle `name` and with it all its roots.
export function removeTrustBundle(dir, name) {
  checkName(name);
  const target = joinRaw(bundlesDir(dir), name);
  if (!isDir(target)) throw new Error(`no trust bundle named "${name}"`);
  fs.rmSync(target, { recursive: true, force: true });
}
