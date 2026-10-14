// Local decision log (spec/08): one JSON line per verification, so a
// security team has evidence of what ran and why without a server. Mirrors
// promptsign-core's decision_log.rs. The managed policy or the user's policy
// turns it on with `decision_log: true`, and a command can name a file of its
// own. A failed write never changes a verdict.

import fs from 'node:fs';
import path from 'node:path';
import { promptsignHome } from './keys.mjs';
import { managedDir } from './managed.mjs';
import { findUserPolicy, loadManagedPolicy } from './policy.mjs';

export const DECISION_LOG_SCHEMA = 'promptsign/decision-log/v1';
export const DEFAULT_MAX_BYTES = 10 * 1024 * 1024;
// Rotated copies kept beside the live file, <file>.1 (newest) to <file>.4.
export const ROTATED_COPIES = 4;

// The OS user the verifier runs as, from the environment.
export function user() {
  return process.env.USER || process.env.USERNAME || 'unknown';
}

// The log's file name inside a log directory. Each user gets a file of their
// own, so users of one machine never write to each other's.
export function fileName() {
  return `decisions-${user().replace(/[^A-Za-z0-9._-]/g, '_')}.jsonl`;
}

// The sink a policy layer asks for, if it turns the log on. A relative
// decision_log_dir resolves against the directory of the policy file.
function layerSink(policy, source, defaultDir) {
  if (policy.decision_log !== true) return null;
  const dir =
    policy.decision_log_dir != null
      ? path.resolve(path.dirname(source), policy.decision_log_dir)
      : defaultDir;
  return {
    path: path.join(dir, fileName()),
    maxBytes: policy.decision_log_max_bytes ?? DEFAULT_MAX_BYTES,
  };
}

// Every file this process logs to: the managed policy's, the user policy's,
// then explicitFile (a command's own flag). A managed policy that does not
// load still logs to the managed default, so its failures show up there.
export function sinks(explicitPolicy, explicitFile) {
  const managedDefault = path.join(managedDir(), 'log');
  const out = [];
  let managed;
  try {
    managed = loadManagedPolicy();
  } catch {
    out.push({ path: path.join(managedDefault, fileName()), maxBytes: DEFAULT_MAX_BYTES });
  }
  if (managed) out.push(layerSink(managed.policy, managed.source, managedDefault));
  try {
    const own = findUserPolicy(explicitPolicy);
    if (own) out.push(layerSink(own.policy, own.source, path.join(promptsignHome(), 'log')));
  } catch {
    // A user policy that does not load turns nothing on.
  }
  if (explicitFile) out.push({ path: explicitFile, maxBytes: DEFAULT_MAX_BYTES });

  const unique = [];
  for (const s of out) {
    if (s && !unique.some((u) => u.path === s.path)) unique.push(s);
  }
  return unique;
}

// ctx: { verifier, harness?, event }. Keys follow the wire order, and
// JSON.stringify drops the undefined ones as serde skips absent fields.
function base(ctx, name, result, decision) {
  return {
    schema: DECISION_LOG_SCHEMA,
    time: new Date().toISOString(),
    verifier: ctx.verifier,
    user: user(),
    harness: ctx.harness ?? undefined,
    event: ctx.event,
    target: undefined,
    name,
    format: undefined,
    signed: false,
    payload_digest: undefined,
    identity: undefined,
    issuer: undefined,
    root: undefined,
    integrated_time: undefined,
    result,
    decision: decision ?? undefined,
    rule: undefined,
    revocation: 'unchecked',
    policy_source: undefined,
    findings: [],
  };
}

// The record of one verification.
export function verifiedRecord(ctx, r, decision) {
  const evidence = r.evidence ?? {};
  return {
    ...base(ctx, r.name, r.action, decision),
    target: path.resolve(r.target),
    format: r.format ?? undefined,
    signed: r.signed,
    payload_digest: evidence.payloadDigest ?? undefined,
    identity: r.identity ?? undefined,
    issuer: r.issuer ?? undefined,
    root: r.root ?? undefined,
    integrated_time: r.integratedTime ?? undefined,
    rule: evidence.rule ?? undefined,
    revocation: evidence.revocation ?? 'unchecked',
    policy_source: r.policySource,
    findings: r.findings,
  };
}

// A verification that could not run.
export function errorRecord(ctx, name, target, message, decision) {
  return {
    ...base(ctx, name, 'error', decision),
    target: target ? path.resolve(target) : undefined,
    findings: [{ level: 'error', message }],
  };
}

// <file> becomes <file>.1, <file>.1 becomes <file>.2, and so on; the oldest
// copy is dropped.
function rotate(file) {
  for (let i = ROTATED_COPIES - 1; i >= 1; i--) {
    if (fs.existsSync(`${file}.${i}`)) fs.renameSync(`${file}.${i}`, `${file}.${i + 1}`);
  }
  fs.renameSync(file, `${file}.1`);
}

// Append text to one sink, rotating first when it would pass the limit.
// Node has no file locks: concurrent writers of one file may rotate twice,
// and each still appends whole lines in a single write.
function appendTo(sink, text) {
  fs.mkdirSync(path.dirname(path.resolve(sink.path)), { recursive: true });
  let len = 0;
  try {
    len = fs.statSync(sink.path).size;
  } catch {
    // no log yet
  }
  if (len > 0 && len + Buffer.byteLength(text) > sink.maxBytes) rotate(sink.path);
  fs.appendFileSync(sink.path, text);
}

// Append records to every sink. Returns one message per sink that could not
// be written, for the caller to report.
export function append(sinkList, records) {
  if (sinkList.length === 0 || records.length === 0) return [];
  const text = records.map((r) => JSON.stringify(r) + '\n').join('');
  const errors = [];
  for (const s of sinkList) {
    try {
      appendTo(s, text);
    } catch (e) {
      errors.push(`decision log ${s.path}: ${e.message}`);
    }
  }
  return errors;
}
