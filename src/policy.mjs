// Trust policy evaluation and TOFU pin store (spec/04-policy.md).
// A signature without policy is meaningless: anyone can validly sign as
// themselves. Policy decides which identities may sign which names.

import fs from 'node:fs';
import path from 'node:path';
import { promptsignHome } from './keys.mjs';

export const POLICY_SCHEMA = 'promptsign/policy/v1';

export const DEFAULT_POLICY = {
  schema: POLICY_SCHEMA,
  default: 'warn',
  rules: [{ pattern: '*', action: 'warn', tofu: true }],
};

export function loadPolicy(explicitPath, projectDir = process.cwd()) {
  const candidates = [
    explicitPath,
    process.env.PROMPTSIGN_POLICY,
    path.join(projectDir, '.promptsign', 'policy.json'),
    path.join(promptsignHome(), 'policy.json'),
  ].filter(Boolean);
  for (const p of candidates) {
    if (fs.existsSync(p)) {
      const policy = JSON.parse(fs.readFileSync(p, 'utf8'));
      if (policy.schema !== POLICY_SCHEMA) throw new Error(`${p}: unsupported policy schema`);
      return { policy, source: p };
    }
    if (p === explicitPath) throw new Error(`policy not found: ${p}`);
  }
  return { policy: DEFAULT_POLICY, source: '(built-in default)' };
}

export function globMatch(pattern, value) {
  const re = new RegExp(
    '^' +
      pattern
        .split('*')
        .map((s) => s.replace(/[.+?^${}()|[\]\\]/g, '\\$&'))
        .join('.*') +
      '$',
  );
  return re.test(value ?? '');
}

export function matchRule(policy, name) {
  const rule = (policy.rules || []).find((r) => globMatch(r.pattern, name));
  return rule || { pattern: '*', action: policy.default || 'warn' };
}

function pinsPath() {
  return path.join(promptsignHome(), 'pins.json');
}

export function loadPins() {
  const p = pinsPath();
  if (!fs.existsSync(p)) return {};
  return JSON.parse(fs.readFileSync(p, 'utf8'));
}

export function savePins(pins) {
  fs.mkdirSync(promptsignHome(), { recursive: true });
  fs.writeFileSync(pinsPath(), JSON.stringify(pins, null, 2) + '\n');
}

// Evaluate a verified signer against policy. `signed: false` means no bundle
// was found at all. Returns { action, findings, pinUpdate } where action is
// the worst outcome: 'pass' | 'warn' | 'fail'.
export function evaluate(policy, { name, identity, keyid, signed }, pins = loadPins()) {
  const rule = matchRule(policy, name);
  const level = rule.action || policy.default || 'warn';
  const findings = [];
  let action = 'pass';
  const raise = (to) => {
    const order = { pass: 0, warn: 1, fail: 2 };
    if (order[to] > order[action]) action = to;
  };
  const violate = (message) => {
    if (level === 'off') return;
    findings.push({ level: level === 'enforce' ? 'error' : 'warn', message });
    raise(level === 'enforce' ? 'fail' : 'warn');
  };

  if (!signed) {
    violate(`unsigned artifact "${name}" (rule: ${rule.pattern})`);
    return { action, findings, rule, pinUpdate: null };
  }

  if (rule.identity && !globMatch(rule.identity, identity)) {
    violate(`identity "${identity}" not allowed for "${name}" (expected ${rule.identity})`);
  }
  if (rule.keyid && rule.keyid !== keyid) {
    violate(`keyid ${keyid.slice(0, 16)}… does not match pinned rule keyid`);
  }

  let pinUpdate = null;
  if (rule.tofu) {
    const pin = pins[name];
    if (pin) {
      if (pin.identity !== identity || pin.keyid !== keyid) {
        // Pin mismatch is always a hard failure: this is the signal for
        // account compromise or repo-transfer attacks (T3).
        findings.push({
          level: 'error',
          message:
            `TOFU pin mismatch for "${name}": previously signed by "${pin.identity}" ` +
            `(key ${pin.keyid.slice(0, 16)}…), now "${identity}" (key ${keyid.slice(0, 16)}…)`,
        });
        raise('fail');
      }
    } else if (action !== 'fail') {
      pinUpdate = { name, identity, keyid, first_seen: new Date().toISOString() };
    }
  }
  return { action, findings, rule, pinUpdate };
}
