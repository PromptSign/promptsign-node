import { test } from 'node:test';
import assert from 'node:assert/strict';
import { evaluate, globMatch, POLICY_SCHEMA } from '../src/policy.mjs';

const policy = {
  schema: POLICY_SCHEMA,
  default: 'warn',
  rules: [
    { pattern: 'anthropic/*', identity: 'https://github.com/anthropic/*', action: 'enforce' },
    { pattern: 'internal/*', action: 'off' },
    { pattern: '*', action: 'warn', tofu: true },
  ],
};

test('glob matching', () => {
  assert.ok(globMatch('anthropic/*', 'anthropic/pdf-skill'));
  assert.ok(!globMatch('anthropic/*', 'anthroplc/pdf-skill'));
  assert.ok(globMatch('*', 'anything'));
});

test('identity mismatch under enforce rule fails', () => {
  const r = evaluate(
    policy,
    {
      name: 'anthropic/pdf-skill',
      identity: 'https://github.com/attacker/repo',
      keyid: 'k1',
      signed: true,
    },
    {},
  );
  assert.equal(r.action, 'fail');
});

test('matching identity under enforce rule passes', () => {
  const r = evaluate(
    policy,
    {
      name: 'anthropic/pdf-skill',
      identity: 'https://github.com/anthropic/skills',
      keyid: 'k1',
      signed: true,
    },
    {},
  );
  assert.equal(r.action, 'pass');
});

test('unsigned artifact: enforce fails, warn warns, off passes', () => {
  assert.equal(evaluate(policy, { name: 'anthropic/x', signed: false }, {}).action, 'fail');
  assert.equal(evaluate(policy, { name: 'community/x', signed: false }, {}).action, 'warn');
  assert.equal(evaluate(policy, { name: 'internal/x', signed: false }, {}).action, 'pass');
});

test('TOFU: first sighting requests a pin, identity change hard-fails', () => {
  const first = evaluate(
    policy,
    { name: 'community/x', identity: 'alice', keyid: 'kA', signed: true },
    {},
  );
  assert.equal(first.action, 'pass');
  assert.ok(first.pinUpdate);

  const pins = { 'community/x': { identity: 'alice', keyid: 'kA', first_seen: 'x' } };
  const same = evaluate(
    policy,
    { name: 'community/x', identity: 'alice', keyid: 'kA', signed: true },
    pins,
  );
  assert.equal(same.action, 'pass');
  assert.equal(same.pinUpdate, null);

  const changed = evaluate(
    policy,
    { name: 'community/x', identity: 'mallory', keyid: 'kM', signed: true },
    pins,
  );
  assert.equal(changed.action, 'fail'); // pin mismatch is always hard
});

test('issuer and trust_root rules glob the keyless issuer and the root name', () => {
  const p = {
    schema: POLICY_SCHEMA,
    rules: [
      {
        pattern: 'acme/*',
        issuer: 'https://token.actions.githubusercontent.com',
        trust_root: 'acme/*',
        action: 'enforce',
      },
    ],
  };
  const input = {
    name: 'acme/x',
    identity: 'https://github.com/acme/x/.github/workflows/s.yml@refs/tags/v1',
    keyid: '',
    issuer: 'https://token.actions.githubusercontent.com',
    root: 'acme/prod',
    signed: true,
  };
  assert.equal(evaluate(p, input, {}).action, 'pass');
  const wrongRoot = evaluate(p, { ...input, root: 'sigstore-public' }, {});
  assert.equal(wrongRoot.action, 'fail');
  assert.equal(
    wrongRoot.findings[0].message,
    'trust root "sigstore-public" not allowed for "acme/x" (expected acme/*)',
  );
  // A keyful bundle has no issuer and no root, so both rules fail it.
  const keyful = evaluate(p, { name: 'acme/x', identity: 'k', keyid: 'k1', signed: true }, {});
  assert.deepEqual(
    keyful.findings.map((f) => f.message),
    [
      'issuer "" not allowed for "acme/x" (expected https://token.actions.githubusercontent.com)',
      'trust root "" not allowed for "acme/x" (expected acme/*)',
    ],
  );
});

test('keyless pins bind identity and issuer; a CI workflow pin ignores its git ref', () => {
  const p = { schema: POLICY_SCHEMA, rules: [{ pattern: '*', action: 'warn', tofu: true }] };
  const iss = 'https://token.actions.githubusercontent.com';
  const wf = 'https://github.com/acme/x/.github/workflows/s.yml';
  const first = evaluate(
    p,
    { name: 'x', identity: `${wf}@refs/tags/v1`, keyid: '', issuer: iss, signed: true },
    {},
  );
  assert.deepEqual(Object.keys(first.pinUpdate), [
    'name',
    'identity',
    'keyid',
    'issuer',
    'first_seen',
  ]);
  const pins = { x: first.pinUpdate };
  const nextTag = evaluate(
    p,
    { name: 'x', identity: `${wf}@refs/tags/v2`, keyid: '', issuer: iss, signed: true },
    pins,
  );
  assert.equal(nextTag.action, 'pass');
  const otherIdp = evaluate(
    p,
    { name: 'x', identity: `${wf}@refs/tags/v2`, keyid: '', issuer: 'https://evil', signed: true },
    pins,
  );
  assert.equal(otherIdp.action, 'fail');
  assert.match(
    otherIdp.findings[0].message,
    /\(issuer "https:\/\/token\.actions\.githubusercontent\.com" → "https:\/\/evil"\)$/,
  );
  // keyful to keyless is a signer change: the keyid and issuer both differ.
  const keyful = { x: { name: 'x', identity: 'alice', keyid: 'k1', first_seen: 't' } };
  const switched = evaluate(
    p,
    { name: 'x', identity: 'alice', keyid: '', issuer: iss, signed: true },
    keyful,
  );
  assert.equal(switched.action, 'fail');
  assert.match(switched.findings[0].message, /\(issuer "-" → "https:\/\/token/);
});
