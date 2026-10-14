// `trust` subcommands (spec/07 §2.2, §5): add a root or a trust bundle,
// list and remove them, and fetch the built-in Sigstore root and installed
// bundles. Only `trust fetch` and `trust add <url>` touch the network.
// Output matches the Rust CLI's line for line.

import fs from 'node:fs';
import { parseCertificate, pemBodies } from './der.mjs';
import { parseRekorLogs, trustDir, trustedLogIds } from './keyless.mjs';
import { managedTrustDir } from './managed.mjs';
import { globMatch } from './policy.mjs';
import {
  checkLayerTrustBundle,
  installedLayerBundles,
  layerTrustDir,
  removeTrustBundle,
  storeTrustBundle,
} from './trustbundle.mjs';
import {
  DEFAULT_ROOT,
  addCaRoot,
  addTrustedRoot,
  loadFullRegistry,
  loadRegistry,
  removeRoot,
  rootCaOnly,
  rootFromTrustedRoot,
} from './trustroot.mjs';
import { Repo as TufRepo } from './tuf.mjs';
import { formatIso8601, joinRaw, nowSecs } from './util.mjs';

const DEFAULT_FULCIO = 'https://fulcio.sigstore.dev';
const DEFAULT_REKOR = 'https://rekor.sigstore.dev';
const MAX_BODY = 4 << 20;

const out = (line) => process.stdout.write(line + '\n');

function envUrl(name, fallback) {
  const v = process.env[name];
  return v ? v.replace(/\/+$/, '') : fallback;
}

async function request(url, context) {
  let resp;
  try {
    resp = await fetch(url, {
      headers: { 'user-agent': 'promptsign-reference' },
      signal: AbortSignal.timeout(30_000),
    });
  } catch (e) {
    throw new Error(`${context}: ${e.cause?.message ?? e.message}`);
  }
  if (resp.status >= 400) {
    const body = await resp.text().catch(() => '');
    throw new Error(`${context}: HTTP ${resp.status}: ${body.trim()}`);
  }
  return resp;
}

// A GET of at most 4 MiB, for documents such as trust bundles.
export async function httpGet(url) {
  const resp = await request(url, url);
  const chunks = [];
  let size = 0;
  for await (const chunk of resp.body) {
    chunks.push(chunk);
    size += chunk.length;
    if (size >= MAX_BODY) break;
  }
  return Buffer.concat(chunks).subarray(0, MAX_BODY);
}

// Plain HTTP only reaches this machine, which is what tests and a local
// mirror need. Anything else is fetched over https.
function isLoopbackHttp(url) {
  return ['http://127.0.0.1:', 'http://127.0.0.1/', 'http://localhost:', 'http://localhost/'].some(
    (p) => url.startsWith(p),
  );
}

function readFile(p) {
  try {
    return fs.readFileSync(p);
  } catch (e) {
    throw new Error(`${p}: ${e.message}`);
  }
}

// The bundle bytes and its sidecar from a URL (<url> and <url>.psig.json) or
// a file (<file> and <file>.psig.json), plus the URL to refresh from.
async function readSource(src) {
  if (src.startsWith('https://') || isLoopbackHttp(src)) {
    const bytes = await httpGet(src);
    const sidecar = await httpGet(`${src}.psig.json`);
    return { bytes, sidecar, url: src };
  }
  if (src.startsWith('http://')) {
    throw new Error(`${src}: trust bundles are fetched over https only`);
  }
  return { bytes: readFile(src), sidecar: readFile(`${src}.psig.json`), url: null };
}

function check(managed, name, bytes, sidecar) {
  let parsed;
  try {
    parsed = JSON.parse(sidecar.toString('utf8'));
  } catch (e) {
    throw new Error(`trust bundle signature: ${e.message}`);
  }
  return checkLayerTrustBundle(managed, name, bytes, parsed, nowSecs());
}

const kindOf = (r) => (r.isCaOnly() ? 'certificate' : 'keyless');

function describe(c) {
  const b = c.bundle;
  out(`trust bundle: ${b.name}, version ${b.version}`);
  if (b.suggestedName && b.suggestedName !== b.name) out(`publisher name: ${b.suggestedName}`);
  out(`valid:        issued ${formatIso8601(b.issued)}, expires ${formatIso8601(b.expires)}`);
  out(`signed by:    ${c.signer.identity} (issuer ${c.signer.issuer}, root ${c.signer.root})`);
  for (const r of b.roots) {
    out(`root:         ${r.name} (${kindOf(r)}) ${r.subject}  sha256:${r.fingerprint}`);
  }
}

function readLineSync() {
  const buf = Buffer.alloc(1);
  let line = '';
  for (;;) {
    let n;
    try {
      n = fs.readSync(0, buf, 0, 1, null);
    } catch (e) {
      if (e.code === 'EAGAIN') continue;
      if (e.code === 'EOF') break;
      throw e;
    }
    if (n === 0 || buf[0] === 0x0a) break;
    line += String.fromCharCode(buf[0]);
  }
  return line;
}

// Ask on the terminal, or require --yes when there is none.
function confirm(question, yes, command) {
  if (yes) return;
  if (!process.stdin.isTTY) {
    throw new Error(`${command}: confirm with --yes when not running interactively`);
  }
  process.stdout.write(`${question} [y/N] `);
  if (!['y', 'Y', 'yes'].includes(readLineSync().trim())) {
    throw new Error(`${command}: not added`);
  }
}

// `trust add <name> <url|file> [--signer <glob>] [--yes] [--managed]`. A
// first install trusts the bundle's own signers, so it needs the user's
// consent. An update signed by a signer the installed version names does
// not. `managed` installs into the machine's managed trust directory.
export async function addBundle(name, src, signer, yes, managed = false) {
  const { bytes, sidecar, url } = await readSource(src);
  const c = check(managed, name, bytes, sidecar);
  const dir = layerTrustDir(managed);
  describe(c);
  if (c.unchanged) {
    out(`trust bundle "${name}" is already at version ${c.bundle.version}`);
    return;
  }
  if (!c.update) {
    if (signer !== undefined && !globMatch(signer, c.signer.identity)) {
      throw new Error(
        `trust add: the bundle is signed by "${c.signer.identity}", which does not match --signer ${signer}`,
      );
    }
    confirm(
      `Trust every signature that chains to these roots, and future versions from this signer, as "${name}"?`,
      yes,
      'trust add',
    );
  }
  storeTrustBundle(dir, name, bytes, sidecar, url);
  out(
    `${c.update ? 'updated' : 'installed'} trust bundle "${name}" version ${c.bundle.version} in ${joinRaw(dir, 'bundles', name)}`,
  );
}

// `trust add <name> --ca <pem>` or `--trusted-root <json>`: one root from
// files. The command shows it and asks before storing it in the user's
// registry, or with `managed` in the machine's.
export function addRoot(name, { ca, trustedRoot, yes, managed = false }) {
  if ((ca === undefined) === (trustedRoot === undefined)) {
    throw new Error(
      'trust add: give a bundle <url|file>, or exactly one of --ca <pem> or --trusted-root <json>',
    );
  }
  const readDoc = () => {
    const bytes = readFile(trustedRoot);
    try {
      return JSON.parse(bytes.toString('utf8'));
    } catch (e) {
      throw new Error(`${trustedRoot}: ${e.message}`);
    }
  };
  const candidate =
    ca !== undefined ? rootCaOnly(name, readFile(ca)) : rootFromTrustedRoot(name, readDoc());
  const taken = loadRegistry().some((r) => r.managed && r.name.split('/')[0] === name);
  if (taken && !managed) {
    throw new Error(`trust add: "${name}" is the name of a managed trust root or bundle`);
  }
  const kind = candidate.isCaOnly()
    ? 'certificate (no transparency log; checked at the current time)'
    : 'keyless (CA plus transparency log)';
  out(`root:        ${candidate.subject}`);
  out(`fingerprint: sha256:${candidate.fingerprint}`);
  out(`kind:        ${kind}`);
  confirm(`Trust signatures that chain to this root as "${name}"?`, yes, 'trust add');
  const dir = layerTrustDir(managed);
  const added =
    ca !== undefined ? addCaRoot(dir, name, readFile(ca)) : addTrustedRoot(dir, name, readDoc());
  out(`added trust root "${added.name}" to ${joinRaw(dir, 'roots')}`);
}

export function list() {
  const { roots, bundles, ignored } = loadFullRegistry(nowSecs());
  if (roots.length === 0) out('no trust roots: run "promptsign trust fetch"');
  for (const r of roots) {
    const slash = r.name.indexOf('/');
    const b = slash === -1 ? null : bundles.find((i) => i.bundle.name === r.name.slice(0, slash));
    let from = r.managed ? '  (managed)' : '';
    if (b) {
      from = `  (${b.managed ? 'managed ' : ''}bundle ${b.bundle.name} v${b.bundle.version}, expires ${formatIso8601(b.bundle.expires)}${b.stale ? ', STALE: run promptsign trust fetch' : ''})`;
    }
    out(
      `${r.name.padEnd(20)} ${kindOf(r).padEnd(12)} sha256:${r.fingerprint}  ${r.subject}${from}`,
    );
  }
  for (const note of ignored) out(note);
}

export function remove(name, managed = false) {
  const dir = layerTrustDir(managed);
  let isBundle = false;
  try {
    isBundle = fs.statSync(joinRaw(dir, 'bundles', name)).isDirectory();
  } catch {
    isBundle = false;
  }
  if (isBundle) {
    removeTrustBundle(dir, name);
    out(`removed trust bundle "${name}" and its roots`);
    return;
  }
  removeRoot(dir, name);
  out(`removed trust root "${name}"`);
}

// `trust fetch <name>`, or every installed bundle when `only` is null, in
// the user's trust directory or the managed one. Reports each bundle and
// errors if any could not be refreshed, leaving that one at its installed
// version.
export async function fetchBundles(only, managed = false) {
  const failed = [];
  let seen = false;
  for (const i of installedLayerBundles(managed, nowSecs())) {
    const name = i.bundle.name;
    if (only !== null && only !== name) continue;
    seen = true;
    const url = i.source;
    if (url === null) {
      out(`${name}: installed from a file, nothing to fetch`);
      continue;
    }
    try {
      const { bytes, sidecar } = await readSource(url);
      const c = check(managed, name, bytes, sidecar);
      if (!c.unchanged) storeTrustBundle(layerTrustDir(managed), name, bytes, sidecar, url);
      out(
        c.unchanged
          ? `${name}: up to date (version ${c.bundle.version})`
          : `${name}: version ${i.bundle.version} -> ${c.bundle.version}`,
      );
    } catch (e) {
      out(`${name}: ${e.message}`);
      failed.push(name);
    }
  }
  if (only !== null && !seen) throw new Error(`no trust bundle named "${only}"`);
  if (failed.length > 0) {
    throw new Error(
      `trust fetch: could not refresh ${failed.join(', ')}; the installed version stays`,
    );
  }
}

// Decoded DER of every PEM block with this label, skipping undecodable ones,
// so the loss check ignores line endings, block order and re-wrapping.
function pemBlockDers(pem, label) {
  try {
    return pemBodies(pem, label).map((d) => d.toString('hex'));
  } catch {
    return [];
  }
}

// Refuse to drop trust material that is already on disk: rotation appends,
// and these endpoints serve only what is current.
function ensureNoLoss(file, label, fetched) {
  let existing;
  try {
    existing = fs.readFileSync(file, 'utf8');
  } catch {
    return;
  }
  const incoming = new Set(pemBlockDers(fetched, label));
  const dropped = pemBlockDers(existing, label).filter((d) => !incoming.has(d)).length;
  if (dropped === 0) return;
  const base = file.split(/[\\/]/).pop();
  throw new Error(
    [
      `refusing to overwrite ${file}: it holds ${dropped} entry(s) the fetched root does not.`,
      '',
      'Rotation is append-only. A signature is checked against the log that witnessed it and',
      'the CA that issued its certificate, so discarding retired material invalidates every',
      'signature made under it. These endpoints only ever serve what is current.',
      '',
      'To take the new root and keep the old:',
      '    scratch=$(mktemp -d)',
      '    PROMPTSIGN_TRUST_DIR=$scratch promptsign trust fetch',
      `    cat $scratch/${base} >> ${file}`,
      '',
      'Or `promptsign trust fetch --force` to overwrite anyway and accept the loss.',
    ].join('\n'),
  );
}

const SIGNING_CONFIG_MEDIA_TYPE = 'application/vnd.dev.sigstore.signingconfig.v0.2+json';

// The public trusted_root.json, which adds the Rekor v2 log and the timestamp
// authority to the pinned pair, and the public signing config, both from
// Sigstore's TUF repository. A private deployment named by
// PROMPTSIGN_FULCIO_URL or PROMPTSIGN_REKOR_URL skips them unless
// PROMPTSIGN_TUF_URL names its own repository.
async function tufDocuments(dir) {
  const set = (v) => Boolean(process.env[v]);
  if ((set('PROMPTSIGN_FULCIO_URL') || set('PROMPTSIGN_REKOR_URL')) && !set('PROMPTSIGN_TUF_URL')) {
    return [];
  }
  const [trustedRoot, signingConfig] = await new TufRepo(dir).fetchTargets([
    'trusted_root.json',
    'signing_config.v0.2.json',
  ]);
  // Validated before anything is written, like the pair.
  let doc;
  try {
    doc = JSON.parse(trustedRoot.toString('utf8'));
    rootFromTrustedRoot(DEFAULT_ROOT, doc);
  } catch (e) {
    throw new Error(`trusted_root.json: ${e.message}`);
  }
  let config;
  try {
    config = JSON.parse(signingConfig.toString('utf8'));
  } catch (e) {
    throw new Error(`signing_config.v0.2.json: ${e.message}`);
  }
  if (config?.mediaType !== SIGNING_CONFIG_MEDIA_TYPE) {
    throw new Error(
      `signing_config.v0.2.json: signing config: mediaType is not ${SIGNING_CONFIG_MEDIA_TYPE}`,
    );
  }
  return [
    ['trusted_root.json', trustedRoot],
    ['signing_config.json', signingConfig],
  ];
}

// Cache the public Fulcio CA chain and Rekor key (the built-in root), and the
// public trusted_root.json and signing config, so keyless verification is
// offline from then on. It fetches and checks everything before it writes
// anything. `managed` writes the managed trust directory instead.
export async function fetchPublicRoot(force, managed = false) {
  const dir = managed ? managedTrustDir() : trustDir();
  fs.mkdirSync(dir, { recursive: true });
  const fulcio = envUrl('PROMPTSIGN_FULCIO_URL', DEFAULT_FULCIO);
  const rekor = envUrl('PROMPTSIGN_REKOR_URL', DEFAULT_REKOR);
  const caPem = await (await request(`${fulcio}/api/v1/rootCert`, 'Fulcio')).text();
  // Validate before persisting.
  let certs;
  try {
    certs = pemBodies(caPem, 'CERTIFICATE').map(parseCertificate);
  } catch (e) {
    throw new Error(`certificate chain: ${e.message}`);
  }
  if (certs.length === 0) throw new Error('empty certificate chain');
  const rekorPem = await (await request(`${rekor}/api/v1/log/publicKey`, 'Rekor')).text();
  if (pemBlockDers(rekorPem, 'PUBLIC KEY').length === 0) {
    throw new Error('Rekor: response is not a PEM public key');
  }
  const documents = await tufDocuments(dir);
  const fulcioPath = joinRaw(dir, 'fulcio.pem');
  const rekorPath = joinRaw(dir, 'rekor.pub');
  if (!force) {
    ensureNoLoss(fulcioPath, 'CERTIFICATE', caPem);
    ensureNoLoss(rekorPath, 'PUBLIC KEY', rekorPem);
  }
  fs.writeFileSync(fulcioPath, caPem);
  fs.writeFileSync(rekorPath, rekorPem);
  out(`wrote ${fulcioPath}`);
  out(`wrote ${rekorPath}`);
  // The TUF documents replace what is there without the check above. Sigstore
  // signs them with its root keys and keeps retired logs and CAs in them with
  // closed windows, so an entry that disappears is one Sigstore removed on
  // purpose.
  for (const [name, bytes] of documents) {
    const p = joinRaw(dir, name);
    fs.writeFileSync(p, bytes);
    out(`wrote ${p}`);
  }
  out(`rekor log id: ${parseRekorLogs(rekorPem)[0].logId}`);
}

export function show() {
  out(`trust dir: ${trustDir()}`);
  trustedLogIds().forEach((id, i) =>
    out(i === 0 ? `rekor log id: ${id}` : `  also trusted: ${id}`),
  );
}
