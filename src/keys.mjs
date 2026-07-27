// Local Ed25519 key management (v1). Phase 2 replaces long-lived local keys
// with keyless OIDC-bound short-lived certificates; the bundle format already
// carries the signer block needed for that transition.

import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { sha256 } from './canonicalize.mjs';

export function promptsignHome() {
  return process.env.PROMPTSIGN_HOME || path.join(os.homedir(), '.promptsign');
}

export function defaultKeyPath() {
  return path.join(promptsignHome(), 'key.pem');
}

export function keygen({ dir = promptsignHome(), force = false, identity } = {}) {
  const keyPath = path.join(dir, 'key.pem');
  const pubPath = path.join(dir, 'key.pub.pem');
  if (fs.existsSync(keyPath) && !force) {
    throw new Error(`key already exists at ${keyPath} (use --force to overwrite)`);
  }
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(keyPath, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
  fs.writeFileSync(pubPath, publicKey.export({ type: 'spki', format: 'pem' }));
  const config = { identity: identity || null };
  fs.writeFileSync(path.join(dir, 'config.json'), JSON.stringify(config, null, 2) + '\n');
  return { keyPath, pubPath, keyid: fingerprint(publicKey) };
}

export function loadPrivateKey(keyPath = defaultKeyPath()) {
  if (!fs.existsSync(keyPath)) {
    throw new Error(`no signing key at ${keyPath} — run "promptsign keygen" first`);
  }
  return crypto.createPrivateKey(fs.readFileSync(keyPath, 'utf8'));
}

export function fingerprint(publicKey) {
  return sha256(publicKey.export({ type: 'spki', format: 'der' }));
}

export function defaultIdentity(publicKey) {
  const cfgPath = path.join(promptsignHome(), 'config.json');
  if (process.env.PROMPTSIGN_IDENTITY) return process.env.PROMPTSIGN_IDENTITY;
  if (fs.existsSync(cfgPath)) {
    try {
      const cfg = JSON.parse(fs.readFileSync(cfgPath, 'utf8'));
      if (cfg.identity) return cfg.identity;
    } catch {
      // fall through to fingerprint identity
    }
  }
  return `key:${fingerprint(publicKey).slice(0, 16)}`;
}
