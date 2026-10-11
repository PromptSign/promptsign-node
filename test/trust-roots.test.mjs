// The verdicts of test/fixtures/trust-roots/README.md (spec/07 §6), checked
// through the CLI with a fresh PROMPTSIGN_HOME each. The fixture tree is a
// byte-identical copy of spec/test/fixtures/trust-roots.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const CLI = path.join(HERE, '..', 'src', 'index.mjs');
const F = path.join(HERE, 'fixtures', 'trust-roots');
const art = (n) => path.join(F, 'artifacts', `${n}.txt`);
const bundle = (n) => path.join(F, 'bundles', n, 'trust-bundle.json');

// A fresh home holding only the pinned public root, as `trust fetch` writes it.
function home({ publicRoot = true } = {}) {
  const h = fs.mkdtempSync(path.join(os.tmpdir(), 'psign-trust-'));
  if (publicRoot) {
    fs.mkdirSync(path.join(h, 'trust'));
    for (const f of ['fulcio.pem', 'rekor.pub']) {
      fs.copyFileSync(path.join(F, 'public', f), path.join(h, 'trust', f));
    }
  }
  return h;
}

// Run the CLI asynchronously (a test server may need to answer it), in
// `cwd` when given.
function runIn(cwd, h, ...args) {
  return new Promise((resolve) => {
    const env = { ...process.env, PROMPTSIGN_HOME: h, NO_COLOR: '1' };
    delete env.PROMPTSIGN_TRUST_DIR;
    delete env.PROMPTSIGN_POLICY;
    const child = spawn(process.execPath, [CLI, ...args], {
      cwd,
      env,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d) => (stdout += d));
    child.stderr.on('data', (d) => (stderr += d));
    child.on('close', (code) => resolve({ code, stdout, stderr }));
  });
}

const run = (h, ...args) => runIn(undefined, h, ...args);

async function verifyJsonIn(cwd, h, name, ...extra) {
  const r = await runIn(cwd, h, 'verify', art(name), '--json', '--no-pin-updates', ...extra);
  return { code: r.code, result: JSON.parse(r.stdout) };
}

const verifyJson = (h, name, ...extra) => verifyJsonIn(undefined, h, name, ...extra);

const installV1 = (h) => run(h, 'trust', 'add', 'acme', bundle('acme-v1'), '--yes');

test('fixtures are present and untouched by line-ending conversion', () => {
  const sidecar = fs.readFileSync(bundle('acme-v1') + '.psig.json', 'utf8');
  assert.ok(!sidecar.includes('\r'), 'test/fixtures must be stored -text');
});

test('the public root signature verifies with no configuration, root sigstore-public', async (t) => {
  const file = path.join(F, 'public', 'public-signed.txt');
  if (!fs.existsSync(file + '.psig.json')) {
    t.skip('public/public-signed.txt has no signature yet');
    return;
  }
  const h = home();
  const r = await run(h, 'verify', file, '--json', '--no-pin-updates');
  assert.equal(r.code, 0, r.stdout + r.stderr);
  assert.equal(JSON.parse(r.stdout).root, 'sigstore-public');
});

test('without acme every artifact fails: its chain ends at an untrusted CA', async () => {
  const h = home();
  for (const n of ['prod-signed', 'before-retirement', 'after-retirement']) {
    const { code, result } = await verifyJson(h, n);
    assert.equal(code, 2);
    assert.equal(result.action, 'fail');
    assert.equal(result.identity, null);
    assert.match(result.findings[0].message, /does not terminate at a trusted root/);
  }
});

test('with no trust root at all, keyless verification says to run trust fetch', async () => {
  const h = home({ publicRoot: false });
  const { code, result } = await verifyJson(h, 'prod-signed');
  assert.equal(code, 2);
  assert.match(
    result.findings[0].message,
    /no Sigstore trust root in .*: run "promptsign trust fetch" first/,
  );
});

test('acme v1 installs, and trust list shows its roots with version and expiry', async () => {
  const h = home();
  const add = await installV1(h);
  assert.equal(add.code, 0, add.stderr);
  assert.match(add.stdout, /^trust bundle: acme, version 1$/m);
  assert.match(
    add.stdout,
    /^signed by: {4}https:\/\/github\.com\/acme\/trust\/.*root acme\/prod\)$/m,
  );
  assert.match(add.stdout, /^installed trust bundle "acme" version 1 in /m);
  for (const f of ['trust-bundle.json', 'trust-bundle.json.psig.json']) {
    assert.ok(
      fs
        .readFileSync(path.join(h, 'trust', 'bundles', 'acme', f))
        .equals(fs.readFileSync(path.join(F, 'bundles', 'acme-v1', f))),
      `${f} stored exactly as given`,
    );
  }
  assert.ok(!fs.existsSync(path.join(h, 'trust', 'bundles', 'acme', 'source.json')));
  const list = await run(h, 'trust', 'list');
  const lines = list.stdout.trimEnd().split('\n');
  assert.deepEqual(
    lines.map((l) => l.split(/\s+/)[0]),
    ['sigstore-public', 'acme/old', 'acme/prod'],
  );
  assert.match(
    lines[2],
    /^acme\/prod {12}keyless {6}sha256:[0-9a-f]{64} {2}CN=acme prod fulcio,O=promptsign tests {2}\(bundle acme v1, expires 2126-01-01T00:00:00Z\)$/,
  );
});

test('with acme installed: prod-signed and before-retirement verify, after-retirement fails on validFor', async () => {
  const h = home();
  await installV1(h);
  const prod = await verifyJson(h, 'prod-signed');
  assert.equal(prod.code, 0);
  assert.equal(prod.result.action, 'pass');
  assert.equal(prod.result.root, 'acme/prod');
  assert.equal(prod.result.identity, 'alice@acme.test');
  assert.equal(prod.result.issuer, 'https://sso.acme.test');
  assert.equal(prod.result.integratedTime, 1790834400);
  assert.equal(prod.result.format, 'promptsign');
  assert.deepEqual(Object.keys(prod.result), [
    'target',
    'policySource',
    'name',
    'identity',
    'issuer',
    'keyid',
    'integratedTime',
    'format',
    'root',
    'signed',
    'action',
    'findings',
  ]);

  const before = await verifyJson(h, 'before-retirement');
  assert.equal(before.code, 0);
  assert.equal(before.result.root, 'acme/old');

  const after = await verifyJson(h, 'after-retirement');
  assert.equal(after.code, 2);
  assert.match(
    after.result.findings[0].message,
    /^invalid signature: certificate authority "CN=acme old fulcio,O=promptsign tests" of trust root "acme\/old" was outside its validity window/,
  );

  const text = await run(h, 'verify', art('prod-signed'));
  assert.match(
    text.stdout,
    /^\[ OK \] prod-signed\.txt signed by alice@acme\.test via https:\/\/sso\.acme\.test \(root acme\/prod\) — /,
  );
  // A keyless TOFU pin binds identity and issuer, never the ephemeral key.
  const pins = JSON.parse(fs.readFileSync(path.join(h, 'pins.json'), 'utf8'));
  assert.deepEqual(Object.keys(pins['prod-signed.txt']), [
    'name',
    'identity',
    'keyid',
    'issuer',
    'first_seen',
  ]);
  assert.equal(pins['prod-signed.txt'].keyid, '');
  assert.equal((await run(h, 'verify', art('prod-signed'))).code, 0);
});

test('v2 updates v1 without a prompt; v1 is then refused as a rollback', async () => {
  const h = home();
  await installV1(h);
  const up = await run(h, 'trust', 'add', 'acme', bundle('acme-v2'));
  assert.equal(up.code, 0, up.stderr);
  assert.match(up.stdout, /^updated trust bundle "acme" version 2 in /m);
  const back = await run(h, 'trust', 'add', 'acme', bundle('acme-v1'), '--yes');
  assert.equal(back.code, 1);
  assert.match(
    back.stderr,
    /version 1 is not newer than the installed version 2: refusing a rollback/,
  );
  const same = await run(h, 'trust', 'add', 'acme', bundle('acme-v2'));
  assert.equal(same.code, 0);
  assert.match(same.stdout, /^trust bundle "acme" is already at version 2$/m);
});

test('an unlisted signer is refused as an install and as an update', async () => {
  const h = home();
  const install = await run(h, 'trust', 'add', 'acme', bundle('acme-v2-unlisted-signer'), '--yes');
  assert.equal(install.code, 1);
  assert.match(
    install.stderr,
    /"https:\/\/github\.com\/mallory\/.*" \(issuer .*\) is not a signer of trust bundle "acme" version 2/,
  );
  assert.ok(!fs.existsSync(path.join(h, 'trust', 'bundles', 'acme')));
  await installV1(h);
  const update = await run(h, 'trust', 'add', 'acme', bundle('acme-v2-unlisted-signer'), '--yes');
  assert.equal(update.code, 1);
  assert.match(update.stderr, /is not a signer of trust bundle "acme" version 1/);
  assert.match((await run(h, 'trust', 'list')).stdout, /\(bundle acme v1,/);
});

test('an install needs --yes off a terminal, and --signer must match', async () => {
  const h = home();
  const noYes = await run(h, 'trust', 'add', 'acme', bundle('acme-v1'));
  assert.equal(noYes.code, 1);
  assert.match(noYes.stderr, /trust add: confirm with --yes when not running interactively/);
  const wrong = await run(
    h,
    'trust',
    'add',
    'acme',
    bundle('acme-v1'),
    '--signer',
    'https://github.com/mallory/*',
    '--yes',
  );
  assert.equal(wrong.code, 1);
  assert.match(wrong.stderr, /which does not match --signer https:\/\/github\.com\/mallory\/\*/);
  const right = await run(
    h,
    'trust',
    'add',
    'acme',
    bundle('acme-v1'),
    '--signer',
    'https://github.com/acme/*',
    '--yes',
  );
  assert.equal(right.code, 0, right.stderr);
});

test('a stale bundle cannot be installed; stored, it warns, and fails under on_trust_bundle_stale', async () => {
  const h = home();
  const add = await run(h, 'trust', 'add', 'acme', bundle('acme-stale'), '--yes');
  assert.equal(add.code, 1);
  assert.match(add.stderr, /trust bundle "acme" expired at 2026-09-30T00:00:00Z/);

  const dir = path.join(h, 'trust', 'bundles', 'acme');
  fs.mkdirSync(dir, { recursive: true });
  for (const f of fs.readdirSync(path.join(F, 'bundles', 'acme-stale'))) {
    fs.copyFileSync(path.join(F, 'bundles', 'acme-stale', f), path.join(dir, f));
  }
  assert.match((await run(h, 'trust', 'list')).stdout, /STALE: run promptsign trust fetch\)$/m);
  const stale =
    'trust bundle "acme" expired at 2026-09-30T00:00:00Z: run "promptsign trust fetch" to refresh it';
  const warn = await verifyJson(h, 'prod-signed');
  assert.equal(warn.code, 0);
  assert.equal(warn.result.action, 'warn');
  assert.deepEqual(warn.result.findings.at(-1), { level: 'warn', message: stale });

  // A project policy cannot set it.
  const proj = fs.mkdtempSync(path.join(os.tmpdir(), 'psign-proj-'));
  fs.mkdirSync(path.join(proj, '.promptsign'));
  fs.writeFileSync(
    path.join(proj, '.promptsign', 'policy.json'),
    JSON.stringify({ schema: 'promptsign/policy/v1', on_trust_bundle_stale: 'fail' }),
  );
  const fromProject = await verifyJsonIn(proj, h, 'prod-signed');
  assert.equal(fromProject.code, 0);
  assert.match(fromProject.result.policySource, /\(tighten only\)$/);

  fs.writeFileSync(
    path.join(h, 'policy.json'),
    JSON.stringify({ schema: 'promptsign/policy/v1', on_trust_bundle_stale: 'fail' }),
  );
  const fail = await verifyJson(h, 'prod-signed');
  assert.equal(fail.code, 2);
  assert.deepEqual(fail.result.findings.at(-1), { level: 'error', message: stale });
});

test('policy rules: trust_root globs the root name, issuer globs the OIDC issuer', async () => {
  const h = home();
  await installV1(h);
  const pol = path.join(h, 'rules.json');
  fs.writeFileSync(
    pol,
    JSON.stringify({
      schema: 'promptsign/policy/v1',
      rules: [
        {
          pattern: 'prod-*',
          trust_root: 'acme/*',
          issuer: 'https://sso.acme.test',
          action: 'enforce',
        },
        { pattern: 'before-*', trust_root: 'sigstore-public', action: 'enforce' },
        { pattern: '*', issuer: 'https://token.actions.githubusercontent.com', action: 'warn' },
      ],
    }),
  );
  assert.equal((await verifyJson(h, 'prod-signed', '--policy', pol)).code, 0);
  const before = await verifyJson(h, 'before-retirement', '--policy', pol);
  assert.equal(before.code, 2);
  assert.equal(
    before.result.findings[0].message,
    'trust root "acme/old" not allowed for "before-retirement.txt" (expected sigstore-public)',
  );
});

test('named roots: --trusted-root verifies keyless, --ca is a certificate root, duplicates are refused', async () => {
  const h = home();
  const doc = JSON.parse(fs.readFileSync(bundle('acme-v1'), 'utf8'));
  const prodRoot = path.join(h, 'prod-root.json');
  fs.writeFileSync(prodRoot, JSON.stringify(doc.roots.prod));
  const raw = doc.roots.old.certificateAuthorities[0].certChain.certificates[0].rawBytes;
  const oldPem = path.join(h, 'old.pem');
  fs.writeFileSync(
    oldPem,
    `-----BEGIN CERTIFICATE-----\n${raw.match(/.{1,64}/g).join('\n')}\n-----END CERTIFICATE-----\n`,
  );

  const add = await run(h, 'trust', 'add', 'corp', '--trusted-root', prodRoot, '--yes');
  assert.equal(add.code, 0, add.stderr);
  assert.match(add.stdout, /^kind: {8}keyless \(CA plus transparency log\)$/m);
  assert.ok(fs.existsSync(path.join(h, 'trust', 'roots', 'corp.json')));
  const ca = await run(h, 'trust', 'add', 'oldca', '--ca', oldPem, '--yes');
  assert.match(
    ca.stdout,
    /^kind: {8}certificate \(no transparency log; checked at the current time\)$/m,
  );
  const dup = await run(h, 'trust', 'add', 'corp2', '--trusted-root', prodRoot, '--yes');
  assert.match(dup.stderr, /this root is already trusted as "corp"/);

  const prod = await verifyJson(h, 'prod-signed');
  assert.equal(prod.result.root, 'corp');
  // A certificate root never verifies a keyless signature.
  assert.equal((await verifyJson(h, 'before-retirement')).code, 2);
  const clash = await installV1(h);
  assert.match(
    clash.stderr,
    /root "acme\/old" of trust bundle "acme" is already trusted as "oldca"/,
  );

  assert.match((await run(h, 'trust', 'rm', 'corp')).stdout, /^removed trust root "corp"$/m);
  assert.match((await run(h, 'trust', 'rm', 'corp')).stderr, /no trust root named "corp"/);
});

test('a bundle installed from a URL refreshes with trust fetch; refusals keep the installed version', async () => {
  const served = {};
  const server = http.createServer((req, res) => {
    const body = served[req.url];
    res.writeHead(body ? 200 : 404);
    res.end(body ?? 'not found');
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const url = `http://127.0.0.1:${server.address().port}/acme/trust-bundle.json`;
  const serve = (name) => {
    served['/acme/trust-bundle.json'] = fs.readFileSync(bundle(name));
    served['/acme/trust-bundle.json.psig.json'] = fs.readFileSync(bundle(name) + '.psig.json');
  };
  try {
    const h = home();
    serve('acme-v1');
    const add = await run(h, 'trust', 'add', 'acme', url, '--yes');
    assert.equal(add.code, 0, add.stderr);
    assert.equal(
      fs.readFileSync(path.join(h, 'trust', 'bundles', 'acme', 'source.json'), 'utf8'),
      JSON.stringify({ url }, null, 2) + '\n',
    );
    assert.equal((await run(h, 'trust', 'fetch', 'acme')).stdout, 'acme: up to date (version 1)\n');
    serve('acme-v2');
    assert.equal((await run(h, 'trust', 'fetch', 'acme')).stdout, 'acme: version 1 -> 2\n');
    serve('acme-v2-unlisted-signer');
    const bad = await run(h, 'trust', 'fetch', 'acme');
    assert.equal(bad.code, 1);
    assert.match(bad.stderr, /trust fetch: could not refresh acme; the installed version stays/);
    assert.match((await run(h, 'trust', 'list')).stdout, /\(bundle acme v2,/);
    const plain = await run(h, 'trust', 'add', 'x', 'http://example.com/b.json', '--yes');
    assert.match(plain.stderr, /trust bundles are fetched over https only/);
  } finally {
    server.close();
  }
});

test('trust rm removes a bundle and all its roots', async () => {
  const h = home();
  await installV1(h);
  const rm = await run(h, 'trust', 'rm', 'acme');
  assert.equal(rm.stdout, 'removed trust bundle "acme" and its roots\n');
  assert.equal((await verifyJson(h, 'prod-signed')).code, 2);
});
