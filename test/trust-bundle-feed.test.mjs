// A trust bundle's revocationFeed (spec/07 §5.1, spec/06 §3): parsed and
// checked like the Rust verifier, with the same messages.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseTrustBundle } from '../src/trustbundle.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const v1 = JSON.parse(
  fs.readFileSync(
    path.join(HERE, 'fixtures', 'trust-roots', 'bundles', 'acme-v1', 'trust-bundle.json'),
    'utf8',
  ),
);

const withFeed = (feed) =>
  Buffer.from(JSON.stringify(feed === undefined ? v1 : { ...v1, revocationFeed: feed }));

test('a trust bundle names its revocation feed', () => {
  const b = parseTrustBundle(
    'acme',
    withFeed({
      url: 'https://trust.acme.test/revocation.json',
      identity: 'CN=revoker',
      root: 'prod',
    }),
  );
  assert.deepEqual(b.revocationFeed, {
    url: 'https://trust.acme.test/revocation.json',
    identity: 'CN=revoker',
    issuer: null,
    root: 'acme/prod',
  });
  assert.equal(parseTrustBundle('acme', withFeed()).revocationFeed, null);
});

test('a malformed revocationFeed refuses the bundle', () => {
  const message = (feed) => {
    try {
      parseTrustBundle('acme', withFeed(feed));
    } catch (e) {
      return e.message;
    }
    return null;
  };
  assert.equal(message(null), 'trust bundle revocationFeed has no url');
  assert.equal(
    message({ url: 'https://x', root: 'prod' }),
    'trust bundle revocationFeed has no identity',
  );
  assert.equal(
    message({ url: 'https://x', identity: 'i', root: 'staging' }),
    'trust bundle revocationFeed root "staging" is neither sigstore-public nor one of the bundle\'s roots',
  );
  assert.equal(
    message({ url: 'https://x', identity: 'i', issuer: 7, root: 'prod' }),
    'trust bundle revocationFeed issuer is not a string',
  );
});
