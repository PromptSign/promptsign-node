import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { evaluateWithProject, loadEffectivePolicy, POLICY_SCHEMA } from '../src/policy.mjs';

const pol = (rules, def = 'warn') => ({ schema: POLICY_SCHEMA, default: def, rules });

test('a project policy cannot relax the user policy', () => {
  const user = pol([{ pattern: '*', action: 'enforce' }]);
  const project = pol([{ pattern: '*', action: 'off' }], 'off');
  assert.equal(evaluateWithProject(user, project, { name: 'x', signed: false }, {}).action, 'fail');
});

test('a project policy cannot add trust', () => {
  const user = pol([{ pattern: '*', keyid: 'a'.repeat(64), action: 'enforce' }]);
  const project = pol([{ pattern: '*', keyid: 'b'.repeat(64), action: 'enforce' }]);
  const res = evaluateWithProject(
    user,
    project,
    { name: 'x', identity: 'i', keyid: 'b'.repeat(64), signed: true },
    {},
  );
  assert.equal(res.action, 'fail');
});

test('a project policy can tighten, and never touches pins', () => {
  const user = pol([{ pattern: '*', action: 'warn' }]);
  const project = pol([{ pattern: '*', action: 'enforce', tofu: true }]);
  const res = evaluateWithProject(user, project, { name: 'x', signed: false }, {});
  assert.equal(res.action, 'fail');
  assert.ok(res.findings.some((f) => f.message.startsWith('project policy: ')));

  const signed = evaluateWithProject(
    user,
    project,
    { name: 'x', identity: 'me', keyid: 'k', signed: true },
    {
      x: { name: 'x', identity: 'someone-else', keyid: 'k2' },
    },
  );
  assert.equal(signed.action, 'pass');
  assert.equal(signed.pinUpdate, null);
});

test('the project policy is loaded beside the user policy, not instead', () => {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-node-policy-'));
  const userPath = path.join(base, 'user.json');
  fs.mkdirSync(path.join(base, 'repo', '.promptsign'), { recursive: true });
  fs.writeFileSync(userPath, JSON.stringify(pol([], 'enforce')));
  fs.writeFileSync(
    path.join(base, 'repo', '.promptsign', 'policy.json'),
    JSON.stringify(pol([], 'off')),
  );
  const eff = loadEffectivePolicy(userPath, path.join(base, 'repo'));
  assert.equal(eff.policy.default, 'enforce');
  assert.equal(eff.project.default, 'off');
  assert.match(eff.source, /tighten only/);
  assert.equal(loadEffectivePolicy(userPath, base).project, null);
  fs.rmSync(base, { recursive: true, force: true });
});
