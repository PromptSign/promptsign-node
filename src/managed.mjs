// The managed layer (spec/04 "Managed policy", spec/07 §2.4): a directory
// that an administrator owns and users cannot write. Verifiers evaluate its
// policy first, and the user's and the project's policies can only add to it.
// Every user on the machine trusts the roots and trust bundles in its trust
// directory.
//
// Each platform has one fixed location. A project can set environment
// variables for the hooks it runs (Claude Code's project settings, for one),
// so the location cannot come from the environment.

import fs from 'node:fs';
import { joinRaw } from './util.mjs';

export const MANAGED_POLICY_FILE = 'managed-policy.json';
export const MANAGED_REVOCATION_FILE = 'revocation.json';

// The variables lock_env turns off. Each moves a file the verifier reads
// from, and a project can set any of them for a hook.
export const LOCKED_VARS = [
  'PROMPTSIGN_POLICY',
  'PROMPTSIGN_HOME',
  'PROMPTSIGN_TRUST_DIR',
  'PROMPTSIGN_REVOCATION_FILE',
];

// The managed directory this platform defines.
export function platformDir() {
  if (process.platform === 'win32') return 'C:\\ProgramData\\PromptSign';
  if (process.platform === 'darwin') return '/Library/Application Support/PromptSign';
  return '/etc/promptsign';
}

// The platform's managed directory, or $PROMPTSIGN_MANAGED_DIR on a machine
// that has no platform directory. The variable stands in for an absent
// managed layer in tests and trials. It cannot hide one that exists.
export function managedDir() {
  const platform = platformDir();
  if (!fs.existsSync(platform) && process.env.PROMPTSIGN_MANAGED_DIR) {
    return process.env.PROMPTSIGN_MANAGED_DIR;
  }
  return platform;
}

export function managedPolicyPath() {
  return joinRaw(managedDir(), MANAGED_POLICY_FILE);
}

// Managed roots and trust bundles, laid out like the user's trust directory.
export function managedTrustDir() {
  return joinRaw(managedDir(), 'trust');
}

export function managedRevocationPath() {
  return joinRaw(managedDir(), MANAGED_REVOCATION_FILE);
}

// True when the managed policy sets lock_env. A managed policy that does not
// parse counts as locked: verification fails on it anyway, and the verifier
// should not read from a location the environment chose meanwhile.
export function envLocked() {
  let text;
  try {
    text = fs.readFileSync(managedPolicyPath(), 'utf8');
  } catch {
    return false;
  }
  try {
    return JSON.parse(text)?.lock_env === true;
  } catch {
    return true;
  }
}

// A non-empty environment variable, unless the managed policy locks the
// environment.
export function envOverride(name) {
  const value = process.env[name];
  if (!value) return undefined;
  return envLocked() ? undefined : value;
}
