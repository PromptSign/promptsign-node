// A TUF client (TUF 1.0, "detailed client workflow") for the documents
// `trust fetch` takes from Sigstore's TUF repository: the public
// trusted_root.json and signing config. The chain of root metadata starts at
// the root this package ships, so the client checks what the CDN serves
// against keys the root's signers hold offline, and TLS carries none of the
// trust. It looks up top-level targets and does not follow delegations. Same
// checks, order and messages as the Rust CLI's tuf.rs.

import crypto from 'node:crypto';
import fs from 'node:fs';
import { trustDir } from './keyless.mjs';
import { formatIso8601, joinRaw, nowSecs, parseIso8601 } from './util.mjs';

export const DEFAULT_TUF_URL = 'https://tuf-repo-cdn.sigstore.dev';

// Sigstore's root metadata, version 15. The client reaches a newer root by
// fetching and verifying each version after it.
const EMBEDDED_ROOT = new URL('./tuf-root.json', import.meta.url);

const MAX_ROOT_ROTATIONS = 1024;
const MAX_ROOT_BYTES = 512 * 1024;
const MAX_TIMESTAMP_BYTES = 16 * 1024;
const MAX_METADATA_BYTES = 4 << 20;

// The DER prefix of an Ed25519 SubjectPublicKeyInfo, before the raw key.
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

function envUrl(name, fallback) {
  const v = process.env[name];
  return v ? v.replace(/\/+$/, '') : fallback;
}

function cacheName(url) {
  const i = url.indexOf('://');
  const rest = i === -1 ? url : url.slice(i + 3);
  return rest.replace(/[^A-Za-z0-9.-]/g, '_');
}

function parse(bytes, what) {
  try {
    return JSON.parse(bytes.toString('utf8'));
  } catch (e) {
    throw new Error(`${what}: ${e.message}`);
  }
}

function version(meta) {
  const v = meta?.signed?.version;
  if (!Number.isSafeInteger(v) || v < 0) throw new Error('metadata has no version');
  return v;
}

function versionOf(meta, what) {
  const v = meta?.version;
  if (!Number.isSafeInteger(v) || v < 0) throw new Error(`${what}: no version`);
  return v;
}

// The checks every metadata file gets besides its signatures.
function checkSigned(meta, ty, expected) {
  const signed = meta?.signed ?? {};
  if (signed._type !== ty) throw new Error(`${ty}.json: _type is not "${ty}"`);
  const sv = signed.spec_version;
  if (!(typeof sv === 'string' && (sv === '1' || sv.startsWith('1.')))) {
    throw new Error(`${ty}.json: unsupported spec_version`);
  }
  const v = version(meta);
  if (v === 0) throw new Error(`${ty}.json: version 0`);
  if (expected !== undefined && v !== expected) {
    throw new Error(`${ty}.json: version ${v}, expected ${expected}`);
  }
}

function checkFile(meta, bytes, what, needHash) {
  if (Number.isSafeInteger(meta?.length) && bytes.length !== meta.length) {
    throw new Error(`${what}: length ${bytes.length}, expected ${meta.length}`);
  }
  let checked = 0;
  for (const [alg, want] of Object.entries(meta?.hashes ?? {})) {
    if (alg !== 'sha256' && alg !== 'sha512') continue;
    const got = crypto.createHash(alg).update(bytes).digest('hex');
    if (got !== want) throw new Error(`${what}: ${alg} hash does not match`);
    checked++;
  }
  if (needHash && checked === 0) throw new Error(`${what}: no sha256 or sha512 hash to check`);
}

// The canonical JSON TUF signs (OLPC canonical JSON): keys sorted, no
// whitespace, only `"` and `\` escaped, integers only.
function canonicalString(s) {
  return '"' + s.replace(/[\\"]/g, (c) => '\\' + c) + '"';
}

export function canonicalJson(v) {
  if (v === null) return 'null';
  if (typeof v === 'boolean') return v ? 'true' : 'false';
  if (typeof v === 'number') {
    if (!Number.isInteger(v)) throw new Error('TUF metadata holds a non-integer number');
    return String(v);
  }
  if (typeof v === 'string') return canonicalString(v);
  if (Array.isArray(v)) return '[' + v.map(canonicalJson).join(',') + ']';
  const keys = Object.keys(v).sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)));
  return '{' + keys.map((k) => canonicalString(k) + ':' + canonicalJson(v[k])).join(',') + '}';
}

function unhex(s) {
  if (typeof s !== 'string' || s.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(s)) return null;
  return Buffer.from(s, 'hex');
}

function verifySignature(key, message, sigHex) {
  const sig = unhex(sigHex);
  const pub = typeof key?.keyval?.public === 'string' ? key.keyval.public : '';
  if (!sig) return false;
  try {
    if (key?.scheme === 'ecdsa-sha2-nistp256') {
      const k = pub.includes('-----BEGIN')
        ? crypto.createPublicKey(pub)
        : crypto.createPublicKey({
            key: { kty: 'EC', crv: 'P-256', ...secToJwk(unhex(pub)) },
            format: 'jwk',
          });
      if (k.asymmetricKeyType !== 'ec' || k.asymmetricKeyDetails?.namedCurve !== 'prime256v1') {
        return false;
      }
      return crypto.verify('sha256', message, { key: k, dsaEncoding: 'der' }, sig);
    }
    if (key?.scheme === 'ed25519') {
      const raw = unhex(pub);
      if (!raw || raw.length !== 32 || sig.length !== 64) return false;
      const k = crypto.createPublicKey({
        key: Buffer.concat([ED25519_SPKI_PREFIX, raw]),
        format: 'der',
        type: 'spki',
      });
      return crypto.verify(null, message, k, sig);
    }
  } catch {
    return false;
  }
  return false;
}

// An uncompressed SEC1 P-256 point as JWK coordinates.
function secToJwk(point) {
  if (!point || point.length !== 65 || point[0] !== 4) throw new Error('not an uncompressed point');
  return {
    x: point.subarray(1, 33).toString('base64url'),
    y: point.subarray(33).toString('base64url'),
  };
}

// At least `threshold` distinct keys of `role` signed `meta.signed`.
function verifyRole(meta, keys, role, what) {
  const threshold = role?.threshold;
  if (!Number.isSafeInteger(threshold) || threshold < 1) {
    throw new Error(`${what}: role has no threshold`);
  }
  const keyids = (Array.isArray(role.keyids) ? role.keyids : []).filter(
    (k) => typeof k === 'string',
  );
  const message = Buffer.from(canonicalJson(meta?.signed ?? null), 'utf8');
  // Counted by key material as well as by id, so one key listed under two ids
  // still counts once.
  const counted = [];
  for (const s of Array.isArray(meta?.signatures) ? meta.signatures : []) {
    if (typeof s?.keyid !== 'string' || typeof s?.sig !== 'string') continue;
    const key = keys?.[s.keyid];
    const pub = typeof key?.keyval?.public === 'string' ? key.keyval.public : '';
    if (!keyids.includes(s.keyid) || counted.includes(pub)) continue;
    if (verifySignature(key, message, s.sig)) counted.push(pub);
  }
  if (counted.length < threshold) {
    throw new Error(`${what}: ${counted.length} of the ${threshold} required signatures verify`);
  }
}

export class Repo {
  constructor() {
    this.url = envUrl('PROMPTSIGN_TUF_URL', DEFAULT_TUF_URL);
    const rootPath = process.env.PROMPTSIGN_TUF_ROOT;
    if (rootPath) {
      try {
        this.initialRoot = fs.readFileSync(rootPath);
      } catch (e) {
        throw new Error(`${rootPath}: ${e.message}`);
      }
    } else {
      this.initialRoot = fs.readFileSync(EMBEDDED_ROOT);
    }
    this.cache = joinRaw(trustDir(), 'tuf', cacheName(this.url));
    this.now = nowSecs();
  }

  // The named top-level targets, each checked against the length and hashes
  // the current targets metadata gives for it.
  async fetchTargets(names) {
    const root = await this.updateRoot();
    const keys = root.signed.keys;
    const roles = root.signed.roles ?? {};
    const consistent = root.signed.consistent_snapshot === true;

    const timestampBytes = await this.get(`${this.url}/timestamp.json`, MAX_TIMESTAMP_BYTES);
    const timestamp = parse(timestampBytes, 'timestamp.json');
    verifyRole(timestamp, keys, roles.timestamp, 'timestamp.json');
    checkSigned(timestamp, 'timestamp');
    this.checkExpiry(timestamp, 'timestamp.json');

    const snapshotMeta = timestamp.signed.meta?.['snapshot.json'];
    const snapshotVersion = versionOf(snapshotMeta, 'timestamp.json snapshot.json');
    const oldTimestamp = this.cached('timestamp.json', keys, roles.timestamp);
    if (oldTimestamp) {
      if (version(timestamp) < version(oldTimestamp)) {
        throw new Error('timestamp.json: version is older than the one already seen');
      }
      if (
        snapshotVersion < versionOf(oldTimestamp.signed.meta?.['snapshot.json'], 'snapshot.json')
      ) {
        throw new Error('timestamp.json: names an older snapshot than the one already seen');
      }
    }

    const snapshotBytes = await this.get(
      this.metadataUrl('snapshot.json', snapshotVersion, consistent),
      MAX_METADATA_BYTES,
    );
    checkFile(snapshotMeta, snapshotBytes, 'snapshot.json', false);
    const snapshot = parse(snapshotBytes, 'snapshot.json');
    verifyRole(snapshot, keys, roles.snapshot, 'snapshot.json');
    checkSigned(snapshot, 'snapshot', snapshotVersion);
    this.checkExpiry(snapshot, 'snapshot.json');

    const oldSnapshot = this.cached('snapshot.json', keys, roles.snapshot);
    if (oldSnapshot) {
      for (const [name, meta] of Object.entries(oldSnapshot.signed.meta ?? {})) {
        const now = snapshot.signed.meta?.[name];
        if (now === undefined || now === null)
          throw new Error(`snapshot.json: ${name} was removed`);
        if (versionOf(now, name) < versionOf(meta, name)) {
          throw new Error(`snapshot.json: ${name} went back a version`);
        }
      }
    }

    const targetsMeta = snapshot.signed.meta?.['targets.json'];
    const targetsVersion = versionOf(targetsMeta, 'snapshot.json targets.json');
    const targetsBytes = await this.get(
      this.metadataUrl('targets.json', targetsVersion, consistent),
      MAX_METADATA_BYTES,
    );
    checkFile(targetsMeta, targetsBytes, 'targets.json', false);
    const targets = parse(targetsBytes, 'targets.json');
    verifyRole(targets, keys, roles.targets, 'targets.json');
    checkSigned(targets, 'targets', targetsVersion);
    this.checkExpiry(targets, 'targets.json');

    const out = [];
    for (const name of names) {
      const meta = targets.signed.targets?.[name];
      if (meta === undefined || meta === null) {
        throw new Error(`${name} is not a target of ${this.url}`);
      }
      if (!Number.isSafeInteger(meta.length))
        throw new Error(`targets.json: ${name} has no length`);
      const sha256 = meta.hashes?.sha256;
      let url;
      if (!consistent) url = `${this.url}/targets/${name}`;
      else if (typeof sha256 === 'string') url = `${this.url}/targets/${sha256}.${name}`;
      else throw new Error(`targets.json: ${name} has no sha256 hash`);
      const bytes = await this.get(url, meta.length);
      checkFile(meta, bytes, name, true);
      out.push(bytes);
    }

    this.store('timestamp.json', timestampBytes);
    this.store('snapshot.json', snapshotBytes);
    this.store('targets.json', targetsBytes);
    return out;
  }

  async updateRoot() {
    let root = parse(this.initialRoot, 'initial root.json');
    verifyRole(root, root?.signed?.keys, root?.signed?.roles?.root, 'initial root.json');
    checkSigned(root, 'root');

    const cached = this.cachedRoot(root);
    if (cached) root = cached;

    const start = version(root);
    for (let i = 0; i < MAX_ROOT_ROTATIONS; i++) {
      const next = version(root) + 1;
      const what = `${next}.root.json`;
      const bytes = await this.getOptional(`${this.url}/${next}.root.json`, MAX_ROOT_BYTES);
      if (bytes === null) break;
      const candidate = parse(bytes, what);
      verifyRole(candidate, root.signed.keys, root.signed.roles?.root, what);
      verifyRole(candidate, candidate?.signed?.keys, candidate?.signed?.roles?.root, what);
      checkSigned(candidate, 'root', next);
      this.store('root.json', bytes);
      root = candidate;
    }

    this.checkExpiry(root, 'root.json');
    // New root keys can mean new timestamp and snapshot keys, which the stored
    // copies were not signed with.
    if (version(root) !== start) {
      for (const name of ['timestamp.json', 'snapshot.json', 'targets.json']) {
        fs.rmSync(joinRaw(this.cache, name), { force: true });
      }
    }
    return root;
  }

  cachedRoot(trusted) {
    let cached;
    try {
      cached = parse(fs.readFileSync(joinRaw(this.cache, 'root.json')), 'root.json');
      checkSigned(cached, 'root');
      verifyRole(cached, cached.signed.keys, cached.signed.roles?.root, 'root.json');
    } catch {
      return null;
    }
    return version(cached) > version(trusted) ? cached : null;
  }

  cached(name, keys, role) {
    try {
      const meta = parse(fs.readFileSync(joinRaw(this.cache, name)), name);
      verifyRole(meta, keys, role, name);
      return meta;
    } catch {
      return null;
    }
  }

  store(name, bytes) {
    fs.mkdirSync(this.cache, { recursive: true });
    fs.writeFileSync(joinRaw(this.cache, name), bytes);
  }

  metadataUrl(name, v, consistent) {
    return consistent ? `${this.url}/${v}.${name}` : `${this.url}/${name}`;
  }

  checkExpiry(meta, what) {
    const expires = parseIso8601(meta?.signed?.expires);
    if (expires === null) throw new Error(`${what}: expires is not an RFC 3339 time`);
    if (this.now >= expires) throw new Error(`${what} expired at ${formatIso8601(expires)}`);
  }

  async get(url, max) {
    const bytes = await this.getOptional(url, max);
    if (bytes === null) throw new Error(`${url}: not found`);
    return bytes;
  }

  // A GET where a missing file is null. Object stores answer 403 as well as
  // 404 for a key that does not exist.
  async getOptional(url, max) {
    // An explicit timer, not AbortSignal.timeout, so this code can clear it:
    // on Windows, exiting while one is still armed trips an assertion inside
    // libuv instead of returning the exit code.
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 30_000);
    try {
      let resp;
      try {
        resp = await fetch(url, {
          headers: { 'user-agent': 'promptsign-reference' },
          signal: controller.signal,
        });
      } catch (e) {
        throw new Error(`${url}: ${e.cause?.message ?? e.message}`);
      }
      if (resp.status === 403 || resp.status === 404) {
        await resp.arrayBuffer().catch(() => null);
        return null;
      }
      if (resp.status >= 400) {
        const body = await resp.text().catch(() => '');
        throw new Error(`${url}: HTTP ${resp.status}: ${body.trim()}`);
      }
      const chunks = [];
      let size = 0;
      for await (const chunk of resp.body) {
        chunks.push(chunk);
        size += chunk.length;
        if (size > max) throw new Error(`${url}: larger than ${max} bytes`);
      }
      return Buffer.concat(chunks);
    } finally {
      clearTimeout(timer);
    }
  }
}
