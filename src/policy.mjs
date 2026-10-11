// Trust policy evaluation and TOFU pin store (spec/04-policy.md).
// A signature without policy is meaningless: anyone can validly sign as
// themselves. Policy decides which identities may sign which names.

import fs from 'node:fs';
import path from 'node:path';
import { promptsignHome } from './keys.mjs';
import { joinRaw } from './util.mjs';

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
  const candidates = [
    explicitPath,
    process.env.PROMPTSIGN_POLICY,
    joinRaw(promptsignHome(), 'policy.json'),
  ].filter(Boolean);
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
    's',
  );
  return re.test(value ?? '');
}

export function matchRule(policy, name) {
  const rule = (policy.rules || []).find((r) => globMatch(r.pattern, name));
  return rule || { pattern: '*', action: policy.default || 'warn' };
}

function pinsPath() {
  return joinRaw(promptsignHome(), 'pins.json');
}

export function loadPins() {
  const p = pinsPath();
  if (!fs.existsSync(p)) return {};
  return JSON.parse(fs.readFileSync(p, 'utf8'));
}

// Pins are written sorted by name, each as { name, identity, keyid, issuer?,
// first_seen }: the bytes the Rust CLI writes, so both can share one store.
export function savePins(pins) {
  fs.mkdirSync(promptsignHome(), { recursive: true });
  const sorted = {};
  for (const name of Object.keys(pins).sort()) {
    const { identity, keyid, issuer, first_seen } = pins[name];
    sorted[name] = { name: pins[name].name ?? name, identity, keyid, issuer, first_seen };
  }
  fs.writeFileSync(pinsPath(), JSON.stringify(sorted, null, 2) + '\n');
}

// The part of an identity a TOFU pin binds (spec/05 §5). A keyless CI
// identity is a workflow URI ending in @refs/...; every release tag changes
// that suffix, so the pin binds the workflow and ignores the ref. Keyful
// identities are free-form and compared whole.
function pinIdentity(identity, issuer) {
  // A certificate-mode signer is pinned by its root (the issuer carries the
  // root fingerprint), so a rotated leaf under the same root keeps passing.
  if (issuer?.startsWith('x509:')) return '';
  if (issuer == null || !identity.startsWith('https://')) return identity;
  const at = identity.indexOf('@refs/');
  return at === -1 ? identity : identity.slice(0, at);
}

// Evaluate a verified signer against policy. `signed: false` means no bundle
// was found at all. `issuer` is set only for keyless signers (whose `keyid`
// is then empty: pins must not bind ephemeral keys), and `root` is the
// registry root the signature chained to. Returns { action, findings,
// pinUpdate } where action is the worst outcome: 'pass' | 'warn' | 'fail'.
export function evaluate(policy, input, pins = loadPins()) {
  const { name, signed, issuer = null, root = null } = input;
  const identity = input.identity ?? '';
  const keyid = input.keyid ?? '';
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

  if (rule.identity != null && !globMatch(rule.identity, identity)) {
    violate(`identity "${identity}" not allowed for "${name}" (expected ${rule.identity})`);
  }
  // Keyful bundles have no issuer, so an issuer rule fails them: "must be
  // signed keyless via this IdP" is exactly what the rule expresses.
  if (rule.issuer != null && !globMatch(rule.issuer, issuer ?? '')) {
    violate(`issuer "${issuer ?? ''}" not allowed for "${name}" (expected ${rule.issuer})`);
  }
  if (rule.trust_root != null && !globMatch(rule.trust_root, root ?? '')) {
    violate(`trust root "${root ?? ''}" not allowed for "${name}" (expected ${rule.trust_root})`);
  }
  if (rule.keyid != null && rule.keyid !== keyid) {
    violate(`keyid ${keyid.slice(0, 16)}… does not match pinned rule keyid`);
  }

  let pinUpdate = null;
  if (rule.tofu === true) {
    const pin = pins[name];
    if (pin) {
      const pinIssuer = pin.issuer ?? null;
      const issuerChanged = (pinIssuer ?? '') !== (issuer ?? '');
      const identityChanged =
        pinIdentity(pin.identity, pinIssuer) !== pinIdentity(identity, issuer);
      if (identityChanged || pin.keyid !== keyid || issuerChanged) {
        // Pin mismatch is always a hard failure: this is the signal for
        // account compromise or repo-transfer attacks (T3).
        const issuerNote = issuerChanged
          ? ` (issuer "${pinIssuer ?? '-'}" → "${issuer ?? '-'}")`
          : '';
        findings.push({
          level: 'error',
          message:
            `TOFU pin mismatch for "${name}": previously signed by "${pin.identity}" ` +
            `(key ${pin.keyid.slice(0, 16)}…), now "${identity}" (key ${keyid.slice(0, 16)}…)${issuerNote}`,
        });
        raise('fail');
      }
    } else if (action !== 'fail') {
      pinUpdate = {
        name,
        identity,
        keyid,
        issuer: issuer ?? undefined,
        first_seen: new Date().toISOString(),
      };
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
    findings: [
      ...res.findings,
      ...extra.findings.map((f) => ({ ...f, message: `project policy: ${f.message}` })),
    ],
  };
}

// The weight of a signature anchored at a stale trust bundle's root (spec/07
// §5.6): "warn" (default) or "fail". Read from the user policy only, so a
// project policy can never set it.
export function onTrustBundleStale(userPolicy) {
  return userPolicy.on_trust_bundle_stale === 'fail' ? 'fail' : 'warn';
}
