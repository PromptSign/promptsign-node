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
