// X.509 path checks shared by keyless (Fulcio) verification and the trust
// registry: link signatures, CA constraints on every issuing certificate,
// and the DSSE signature made by the leaf key. Mirrors promptsign-core's
// chain.rs, messages included.

import crypto from 'node:crypto';
import {
  OID,
  basicConstraints,
  extension,
  extKeyUsages,
  isEcdsaSigDer,
  keyUsageHas,
} from './der.mjs';

const KU_DIGITAL_SIGNATURE = 0;
const KU_KEY_CERT_SIGN = 5;

export function publicKeyOf(cert) {
  return crypto.createPublicKey({ key: cert.spkiDer, format: 'der', type: 'spki' });
}

function ecCurve(cert) {
  if (!cert.keyCurveOid) throw new Error('EC key has no curve parameter');
  return cert.keyCurveOid;
}

// ECDSA over a message with the given hash; any problem is just "invalid",
// as in the Rust verifier, which maps every error here to one message.
function verifyEcdsa(spkiDer, curve, hash, message, sig) {
  if (curve !== OID.P256 && curve !== OID.P384) return false;
  if (!isEcdsaSigDer(sig)) return false;
  try {
    const key = crypto.createPublicKey({ key: spkiDer, format: 'der', type: 'spki' });
    return crypto.verify(hash, message, { key, dsaEncoding: 'der' }, sig);
  } catch {
    return false;
  }
}

function verifyEd25519(spkiDer, message, sig, what) {
  let key;
  try {
    key = crypto.createPublicKey({ key: spkiDer, format: 'der', type: 'spki' });
    if (key.asymmetricKeyType !== 'ed25519') throw new Error('not an Ed25519 key');
  } catch (e) {
    throw new Error(`${what}: ${e.message}`);
  }
  if (sig.length !== 64) return null;
  try {
    return crypto.verify(null, message, key, sig);
  } catch {
    return false;
  }
}

// Verify that `child`'s signature was produced by the holder of `parent`'s key.
export function verifySignedBy(child, parent) {
  if (child.sigUnusedBits !== 0) throw new Error('certificate signature has unused bits');
  const alg = child.sigAlgOid;
  const invalid = () => new Error('certificate signature invalid');
  if (alg === OID.ED25519) {
    const ok = verifyEd25519(parent.spkiDer, child.tbs, child.signature, 'parent key');
    if (ok === null) throw new Error('malformed ed25519 sig');
    if (!ok) throw invalid();
    return;
  }
  const rsa = {
    [OID.RSA_SHA256]: 'sha256',
    [OID.RSA_SHA384]: 'sha384',
    [OID.RSA_SHA512]: 'sha512',
  };
  if (rsa[alg]) {
    let ok = false;
    try {
      const key = publicKeyOf(parent);
      ok =
        key.asymmetricKeyType === 'rsa' && crypto.verify(rsa[alg], child.tbs, key, child.signature);
    } catch {
      ok = false;
    }
    if (!ok) throw invalid();
    return;
  }
  if (alg !== OID.ECDSA_SHA256 && alg !== OID.ECDSA_SHA384) {
    throw new Error(`unsupported certificate signature algorithm: ${alg}`);
  }
  if (parent.keyAlgOid !== OID.EC_PUBLIC_KEY) throw new Error('parent key is not an EC key');
  const hash = alg === OID.ECDSA_SHA256 ? 'sha256' : 'sha384';
  if (!verifyEcdsa(parent.spkiDer, ecCurve(parent), hash, child.tbs, child.signature)) {
    throw invalid();
  }
}

// Verify a DSSE signature with the leaf certificate's key: Ed25519, P-256
// with SHA-256, or P-384 with SHA-384 (the hash follows the curve).
export function verifyLeafSignature(leaf, message, sig) {
  if (leaf.keyAlgOid === OID.ED25519) {
    const ok = verifyEd25519(leaf.spkiDer, message, sig, 'leaf key');
    if (ok === null) throw new Error('malformed signature');
    if (!ok) throw new Error('signature verification failed');
    return;
  }
  if (leaf.keyAlgOid !== OID.EC_PUBLIC_KEY) {
    throw new Error(`unsupported leaf key algorithm: ${leaf.keyAlgOid}`);
  }
  const curve = ecCurve(leaf);
  const hash = curve === OID.P384 ? 'sha384' : 'sha256';
  if (!verifyEcdsa(leaf.spkiDer, curve, hash, message, sig)) {
    throw new Error('signature verification failed');
  }
}

function parseExt(cert, oid, what, parse) {
  const ext = extension(cert, oid);
  if (!ext) return null;
  try {
    return parse(ext.value);
  } catch (e) {
    throw new Error(`${what}: ${e.message}`);
  }
}

// A certificate that issues another one must say it is a CA, and its path
// length limit must allow the CA certificates beneath it.
export function checkIssuer(cert, casBelow) {
  const bc = parseExt(cert, OID.BASIC_CONSTRAINTS, 'basic constraints', basicConstraints);
  if (!bc) throw new Error(`"${cert.subject}" issues certificates but has no basic constraints`);
  if (!bc.ca) throw new Error(`"${cert.subject}" issues certificates but is not a CA`);
  if (bc.pathLen !== null && casBelow > bc.pathLen) {
    throw new Error(
      `"${cert.subject}" allows ${bc.pathLen} CA certificates beneath it, the chain has ${casBelow}`,
    );
  }
  const certSign = parseExt(cert, OID.KEY_USAGE, 'key usage', (v) =>
    keyUsageHas(v, KU_KEY_CERT_SIGN),
  );
  if (certSign === false) {
    throw new Error(`"${cert.subject}" issues certificates without the keyCertSign usage`);
  }
}

// A certificate-mode leaf must be allowed to sign: digitalSignature when it
// states key usages, code signing when it states extended ones.
export function checkSigningLeaf(leaf) {
  const sign = parseExt(leaf, OID.KEY_USAGE, 'key usage', (v) =>
    keyUsageHas(v, KU_DIGITAL_SIGNATURE),
  );
  if (sign === false) throw new Error('signing certificate lacks the digitalSignature usage');
  const ekus = parseExt(leaf, OID.EXT_KEY_USAGE, 'extended key usage', extKeyUsages);
  if (ekus && !ekus.some((o) => o === OID.EKU_CODE_SIGNING || o === OID.EKU_ANY)) {
    throw new Error('signing certificate is not issued for code signing');
  }
}

export function isSelfSigned(cert) {
  if (!cert.subjectRaw.equals(cert.issuerRaw)) return false;
  try {
    verifySignedBy(cert, cert);
    return true;
  } catch {
    return false;
  }
}

// Every root a leaf-first chain terminates at, in registry order, as
// [{ root, path }] with `path` leaf first and ending at the pinned
// certificate. Links are checked by position and signature, never by subject
// name; each issuing certificate on the path must be a CA.
export function anchorChain(chain, roots) {
  if (chain.length === 0) throw new Error('empty certificate chain');
  for (let i = 0; i < chain.length - 1; i++) {
    try {
      verifySignedBy(chain[i], chain[i + 1]);
    } catch (e) {
      throw new Error(`chain link ${i}: ${e.message}`);
    }
  }
  const last = chain[chain.length - 1];
  const anchored = [];
  let constraintError = null;
  for (const root of roots) {
    const path = [...chain];
    if (!root.caCerts.some((ca) => ca.der.equals(last.der))) {
      const ca = root.caCerts.find((c) => {
        try {
          verifySignedBy(last, c);
          return true;
        } catch {
          return false;
        }
      });
      if (!ca) continue;
      path.push(ca);
    }
    try {
      for (let i = 1; i < path.length; i++) checkIssuer(path[i], i - 1);
      anchored.push({ root, path });
    } catch (e) {
      constraintError ??= e;
    }
  }
  if (anchored.length === 0 && constraintError) throw constraintError;
  if (anchored.length === 0) {
    throw new Error(
      `certificate chain does not terminate at a trusted root: it ends at "${last.issuer}", which is not in your trust roots (add it with "promptsign trust add" if you trust it)`,
    );
  }
  return anchored;
}
