// Full verification pipeline for one target:
//   1. locate bundle
//   2. verify envelope(crypto)
//   3. re - verify integrity against disk
//   4. evaluate trust policy + TOFU pins.

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { approvalFiles, collect, listingFor, listingOf } from './approval.mjs';
import { hasSignatureMarker, readBundle, verifyEnvelope } from './bundle.mjs';
import { checkIntegrity, walkFiles, CONTEXT_INJECTED } from './manifest.mjs';
import { loadEffectivePolicy, loadPins, savePins } from './policy.mjs';
import { loadFullRegistry } from './trustroot.mjs';
import { formatIso8601, nowSecs } from './util.mjs';

const FORMAT_PROMPTSIGN = 'promptsign';

// What a verification established beyond its verdict, for the decision log
// (spec/08): { payloadDigest, rule, revocation }. Not enumerable, so the JSON
// output stays as it is.
function withEvidence(result, evidence = {}) {
  return Object.defineProperty(result, 'evidence', {
    value: { payloadDigest: null, rule: null, revocation: null, ...evidence },
  });
}

// sha256 of the DSSE payload, the digest a revocation entry matches.
function payloadDigest(bundle) {
  const payload = Buffer.from(bundle?.envelope?.payload ?? '', 'base64');
  return `sha256:${crypto.createHash('sha256').update(payload).digest('hex')}`;
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
// force at least "fail" (downgraded to "warn" only when every policy layer is
// "off", so the warning is surfaced either way). Returns the bumped action.
function applyMarkers(msgs, eff, name, findings, action) {
  if (msgs.length === 0) return action;
  const off = eff.off(name);
  for (const m of msgs) findings.push({ level: off ? 'warn' : 'error', message: m });
  const bump = off ? 'warn' : 'fail';
  return ACTION_RANK[bump] > ACTION_RANK[action] ? bump : action;
}

// A root from a trust bundle past its expiry still verifies, with a finding
// whose weight the managed and user policies set (spec/07 §5.6). Only bundle
// roots, named <bundle>/<root>, can be stale.
function staleBundleFinding(eff, root) {
  const slash = root.indexOf('/');
  if (slash === -1) return null;
  const bundle = root.slice(0, slash);
  const stale = loadFullRegistry(nowSecs()).bundles.find(
    (i) => i.bundle.name === bundle && i.stale,
  );
  if (!stale) return null;
  return {
    level: eff.trustBundleStale() === 'fail' ? 'error' : 'warn',
    message: `trust bundle "${bundle}" expired at ${formatIso8601(stale.bundle.expires)}: run "promptsign trust fetch" to refresh it`,
  };
}

// The approvals of the artifact's content when a layer's rule for `name`
// requires them (spec/09); none otherwise, so verification without approval
// rules reads no extra files. `listing` computes the content listing.
function approvalsFor(eff, name, abs, isDir, listing) {
  if (!eff.needsApprovals(name)) return { approvals: [], findings: [] };
  // This verifier reads no revocation feed, so it cannot tell whether one
  // withdraws an approval. Under a policy that names a feed, none count.
  if (eff.namesRevocationFeed()) {
    return {
      approvals: [],
      findings: [
        {
          level: 'info',
          message:
            'approvals not counted: the policy names a revocation feed, which this verifier does not read',
        },
      ],
    };
  }
  let content;
  try {
    content = listing();
  } catch (e) {
    return {
      approvals: [],
      findings: [{ level: 'info', message: `approvals not checked: ${e.message}` }],
    };
  }
  return collect(approvalFiles(abs, isDir, content.digest), content.digest);
}

// The approvals as the result lists them, the fields of the Rust Approval.
const shown = (approvals) =>
  approvals.length === 0
    ? {}
    : {
        approvals: approvals.map(({ identity, issuer, root, signedAt }) =>
          signedAt == null ? { identity, issuer, root } : { identity, issuer, root, signedAt },
        ),
      };

// Result: { target, policySource, name, version?, kind?, identity, issuer?,
// keyid, integratedTime?, format?, root?, signed, action, findings,
// approvals? }, the field order and omissions of the Rust VerifyResult.
// action: 'pass' | 'warn' | 'fail'
// skipPolicy: crypto + integrity only — used by the signer's post-sign
// self-check, where the local policy/pin store must not gate signing.
export function verifyTarget(target, { policyPath, updatePins = true, skipPolicy = false } = {}) {
  const eff = loadEffectivePolicy(policyPath);
  const policySource = eff.source;
  const abs = path.resolve(target);
  const st = fs.statSync(abs);
  const root = st.isDirectory() ? abs : path.dirname(abs);
  const fallbackName = path.basename(abs).replace(/\.(md|markdown)$/i, '');
  const markerMsgs = contextMarkerMessages(abs, st.isDirectory());

  const found = readBundle(abs);
  if (!found) {
    const approved = approvalsFor(eff, fallbackName, abs, st.isDirectory(), () => listingFor(abs));
    const res = eff.evaluate(
      { name: fallbackName, signed: false, approvals: approved.approvals },
      {},
    );
    const findings = [...approved.findings, ...res.findings];
    const action = applyMarkers(markerMsgs, eff, fallbackName, findings, res.action);
    return withEvidence(
      {
        target,
        policySource,
        name: fallbackName,
        identity: null,
        keyid: null,
        signed: false,
        action,
        findings,
        ...shown(approved.approvals),
      },
      { rule: res.decidedBy },
    );
  }

  let envelope;
  try {
    envelope = verifyEnvelope(found.bundle);
  } catch (e) {
    // A broken/forged signature is never silently ignored: at least a warning
    // even under action "off", a failure under "warn"/"enforce".
    const off = eff.off(fallbackName);
    let action = off ? 'warn' : 'fail';
    const findings = [
      { level: action === 'fail' ? 'error' : 'warn', message: `invalid signature: ${e.message}` },
    ];
    action = applyMarkers(markerMsgs, eff, fallbackName, findings, action);
    return withEvidence({
      target,
      policySource,
      name: fallbackName,
      identity: null,
      keyid: null,
      format: FORMAT_PROMPTSIGN,
      signed: true,
      action,
      findings,
    });
  }

  const { manifest, identity, keyid, issuer, root: trustRoot, signedAt } = envelope;
  // When a keyless signature was made: the log's integratedTime, else the
  // earliest verified timestamp.
  const integratedTime = signedAt;
  const signerFields = {
    name: manifest.name,
    version: manifest.version ?? undefined,
    kind: manifest.kind ?? undefined,
    identity,
    issuer,
    keyid,
    integratedTime,
    format: FORMAT_PROMPTSIGN,
    root: trustRoot,
    signed: true,
  };
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
    return withEvidence(
      { target, policySource: '(skipped)', ...signerFields, action, findings },
      { payloadDigest: payloadDigest(found.bundle) },
    );
  }

  // A tampered artifact fails whatever its approvals say, so skip them.
  const approved =
    action === 'fail'
      ? { approvals: [], findings: [] }
      : approvalsFor(eff, manifest.name, abs, st.isDirectory(), () => listingOf(manifest.files));
  const pins = loadPins();
  // Keyless signers pin identity+issuer, never the ephemeral key (spec/05 §5).
  const res = eff.evaluate(
    {
      name: manifest.name,
      identity,
      keyid: issuer ? '' : keyid,
      issuer,
      root: trustRoot,
      signed: true,
      approvals: approved.approvals,
    },
    pins,
  );
  findings.push(...approved.findings, ...res.findings);
  if (res.action === 'fail') action = 'fail';
  else if (res.action === 'warn' && action === 'pass') action = 'warn';

  action = applyMarkers(markerMsgs, eff, manifest.name, findings, action);

  const stale = trustRoot ? staleBundleFinding(eff, trustRoot) : null;
  if (stale) {
    if (stale.level === 'error') action = 'fail';
    else if (action === 'pass') action = 'warn';
    findings.push(stale);
  }

  if (action !== 'fail' && res.pinUpdate && updatePins) {
    pins[res.pinUpdate.name] = res.pinUpdate;
    savePins(pins);
    findings.push({
      level: 'info',
      message: `pinned "${manifest.name}" to identity "${identity}" (trust on first use)`,
    });
  }

  return withEvidence(
    { target, policySource, ...signerFields, action, findings, ...shown(approved.approvals) },
    { payloadDigest: payloadDigest(found.bundle), rule: res.decidedBy },
  );
}
