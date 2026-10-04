// Full verification pipeline for one target:
//   1. locate bundle
//   2. verify envelope(crypto)
//   3. re - verify integrity against disk
//   4. evaluate trust policy + TOFU pins.

import fs from 'node:fs';
import path from 'node:path';
import { hasSignatureMarker, readBundle, verifyEnvelope } from './bundle.mjs';
import { checkIntegrity, walkFiles, CONTEXT_INJECTED } from './manifest.mjs';
import {
  loadEffectivePolicy,
  loadPins,
  savePins,
  evaluateWithProject,
  matchRule,
} from './policy.mjs';

// True when the effective policy action for `name` is "off" — marker findings
// then degrade from fail to warn (but are always surfaced).
function policyOff(policy, name) {
  const rule = matchRule(policy, name);
  return (rule.action || policy.default || 'warn') === 'off';
}

// An `x-promptsign:` marker inside a context-injected file (CLAUDE.md/AGENTS.md/
// OpenClaw bootstrap files) is never a signature — its presence is a failure.
function markerMessage(abs, display) {
  if (!CONTEXT_INJECTED.has(path.basename(abs))) return null;
  let text;
  try {
    text = fs.readFileSync(abs, 'utf8');
  } catch {
    return null;
  }
  if (!hasSignatureMarker(text)) return null;
  return `${display} carries an embedded x-promptsign marker, which is not a valid signature for context-injected files — treat as untrusted; sign it with a sidecar instead`;
}

function contextMarkerMessages(abs, isDir) {
  const msgs = [];
  if (isDir) {
    let rels;
    try {
      rels = walkFiles(abs);
    } catch {
      return msgs;
    }
    for (const rel of rels) {
      const m = markerMessage(path.join(abs, ...rel.split('/')), rel);
      if (m) msgs.push(m);
    }
  } else {
    const m = markerMessage(abs, path.basename(abs));
    if (m) msgs.push(m);
  }
  return msgs;
}

const ACTION_RANK = { pass: 0, warn: 1, fail: 2 };

// Fold context-injected marker warnings into a result: they add findings and
// force at least "fail" (downgraded to "warn" only under a policy "off", so
// the warning is surfaced either way). Returns the bumped action.
function applyMarkers(msgs, policy, name, findings, action) {
  if (msgs.length === 0) return action;
  const off = policyOff(policy, name);
  for (const m of msgs) findings.push({ level: off ? 'warn' : 'error', message: m });
  const bump = off ? 'warn' : 'fail';
  return ACTION_RANK[bump] > ACTION_RANK[action] ? bump : action;
}

// Result: { target, name, identity, keyid, signed, action, findings }
// action: 'pass' | 'warn' | 'fail'
// skipPolicy: crypto + integrity only — used by the signer's post-sign
// self-check, where the local policy/pin store must not gate signing.
export function verifyTarget(target, { policyPath, updatePins = true, skipPolicy = false } = {}) {
  const { policy, project, source: policySource } = loadEffectivePolicy(policyPath);
  const abs = path.resolve(target);
  const st = fs.statSync(abs);
  const root = st.isDirectory() ? abs : path.dirname(abs);
  const fallbackName = path.basename(abs).replace(/\.(md|markdown)$/i, '');
  const markerMsgs = contextMarkerMessages(abs, st.isDirectory());

  const found = readBundle(abs);
  if (!found) {
    const res = evaluateWithProject(policy, project, { name: fallbackName, signed: false });
    const findings = res.findings;
    const action = applyMarkers(markerMsgs, policy, fallbackName, findings, res.action);
    return {
      target,
      policySource,
      name: fallbackName,
      identity: null,
      keyid: null,
      signed: false,
      action,
      findings,
    };
  }

  let envelope;
  try {
    envelope = verifyEnvelope(found.bundle);
  } catch (e) {
    // A broken/forged signature is never silently ignored: at least a warning
    // even under action "off", a failure under "warn"/"enforce".
    const off = policyOff(policy, fallbackName);
    let action = off ? 'warn' : 'fail';
    const findings = [
      { level: action === 'fail' ? 'error' : 'warn', message: `invalid signature: ${e.message}` },
    ];
    action = applyMarkers(markerMsgs, policy, fallbackName, findings, action);
    return {
      target,
      policySource,
      name: fallbackName,
      identity: null,
      keyid: null,
      signed: true,
      action,
      findings,
    };
  }

  const { manifest, identity, keyid } = envelope;
  const findings = [];
  let action = 'pass';

  // Integrity failures are unconditional: a valid signature over content that
  // no longer matches the disk is a tampered artifact, whatever policy says.
  const integrityRoot = manifest.scope === 'file' ? root : abs;
  for (const problem of checkIntegrity(integrityRoot, manifest)) {
    findings.push({ level: 'error', message: problem });
    action = 'fail';
  }

  if (skipPolicy) {
    // No policy to consult, but a marker on a context-injected file must
    // still fail (self-check safety) — mirror integrity's unconditional fail.
    for (const m of markerMsgs) {
      findings.push({ level: 'error', message: m });
      action = 'fail';
    }
    return {
      target,
      policySource: '(skipped)',
      name: manifest.name,
      version: manifest.version,
      kind: manifest.kind,
      identity,
      keyid,
      signed: true,
      action,
      findings,
    };
  }

  const pins = loadPins();
  const res = evaluateWithProject(
    policy,
    project,
    { name: manifest.name, identity, keyid, signed: true },
    pins,
  );
  findings.push(...res.findings);
  if (res.action === 'fail') action = 'fail';
  else if (res.action === 'warn' && action === 'pass') action = 'warn';

  action = applyMarkers(markerMsgs, policy, manifest.name, findings, action);

  if (action !== 'fail' && res.pinUpdate && updatePins) {
    pins[res.pinUpdate.name] = res.pinUpdate;
    savePins(pins);
    findings.push({
      level: 'info',
      message: `pinned "${manifest.name}" to identity "${identity}" (trust on first use)`,
    });
  }

  return {
    target,
    policySource,
    name: manifest.name,
    version: manifest.version,
    kind: manifest.kind,
    identity,
    keyid,
    signed: true,
    action,
    findings,
  };
}
