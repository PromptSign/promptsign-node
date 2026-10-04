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

function readPolicyFile(p) {
  const policy = JSON.parse(fs.readFileSync(p, 'utf8'));
  if (policy.schema !== POLICY_SCHEMA) throw new Error(`${p}: unsupported policy schema`);
  return policy;
}

// The user's policy (spec/04): explicit path, $PROMPTSIGN_POLICY,
// ~/.promptsign/policy.json, built-in default. A project directory never
// supplies it; see loadProjectPolicy.
export function loadPolicy(explicitPath) {
  const candidates = [explicitPath, process.env.PROMPTSIGN_POLICY, path.join(promptsignHome(), 'policy.json')].filter(
    Boolean,
  );
  for (const p of candidates) {
    if (fs.existsSync(p)) return { policy: readPolicyFile(p), source: p };
    if (p === explicitPath) throw new Error(`policy not found: ${p}`);
  }
  return { policy: DEFAULT_POLICY, source: '(built-in default)' };
}

// A project's own <project>/.promptsign/policy.json, if any. The project is
// untrusted input: this policy can only add requirements to the user's.
export function loadProjectPolicy(projectDir = process.cwd()) {
  const p = path.join(projectDir, '.promptsign', 'policy.json');
  return fs.existsSync(p) ? { policy: readPolicyFile(p), source: p } : null;
}

export function loadEffectivePolicy(explicitPath, projectDir = process.cwd()) {
  const user = loadPolicy(explicitPath);
  const project = loadProjectPolicy(projectDir);
  return {
    policy: user.policy,
    project: project ? project.policy : null,
    source: project ? `${user.source} + ${project.source} (tighten only)` : user.source,
  };
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

// Evaluate the user's policy, then the project's on top of it. The project
// can only make the outcome stricter: its findings are added and the worse
// action wins. It never checks or writes TOFU pins (those are the user's).
export function evaluateWithProject(policy, project, input, pins = loadPins()) {
  const res = evaluate(policy, input, pins);
  if (!project) return res;
  const noTofu = { ...project, rules: (project.rules || []).map((r) => ({ ...r, tofu: false })) };
  const extra = evaluate(noTofu, input, {});
  const order = { pass: 0, warn: 1, fail: 2 };
  return {
    ...res,
    action: order[extra.action] > order[res.action] ? extra.action : res.action,
    findings: [...res.findings, ...extra.findings.map((f) => ({ ...f, message: `project policy: ${f.message}` }))],
  };
}
