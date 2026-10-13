// RFC 3161 signed timestamps (spec/05 §3.3, spec/07 §1). A timestamp
// authority signs the hash of a signature together with the time it saw it.
// That time stands in for a transparency log's integratedTime, which Rekor v2
// entries do not carry. Offline: the authority's certificates come from the
// trust root, the timestamp is stapled in the bundle. Mirrors promptsign-core's
// timestamp.rs, messages included.

import crypto from 'node:crypto';
import { checkIssuer, publicKeyOf, verifySignedBy } from './chain.mjs';
import {
  OID,
  decodeOid,
  extKeyUsages,
  extension,
  isEcdsaSigDer,
  parseCertificate,
  readTlv,
} from './der.mjs';

const SEQUENCE = 0x30;
const SET = 0x31;
const INTEGER = 0x02;
const OCTET_STRING = 0x04;
const OID_TAG = 0x06;
const GENERALIZED_TIME = 0x18;

const SIGNED_DATA = '1.2.840.113549.1.7.2';
const TST_INFO = '1.2.840.113549.1.9.16.1.4';
const CONTENT_TYPE = '1.2.840.113549.1.9.3';
const MESSAGE_DIGEST = '1.2.840.113549.1.9.4';
const SUBJECT_KEY_ID = '2.5.29.14';
const EKU_TIME_STAMPING = '1.3.6.1.5.5.7.3.8';
const SHA = {
  '2.16.840.1.101.3.4.2.1': 'sha256',
  '2.16.840.1.101.3.4.2.2': 'sha384',
  '2.16.840.1.101.3.4.2.3': 'sha512',
};
const ECDSA = {
  '1.2.840.10045.4.3.2': 'sha256',
  '1.2.840.10045.4.3.3': 'sha384',
  '1.2.840.10045.4.3.4': 'sha512',
};
const RSA = {
  '1.2.840.113549.1.1.11': 'sha256',
  '1.2.840.113549.1.1.12': 'sha384',
  '1.2.840.113549.1.1.13': 'sha512',
};
const RSA_ENCRYPTION = '1.2.840.113549.1.1.1';

// A bundle may carry at most this many timestamps.
export const MAX_TIMESTAMPS = 32;

const hex2 = (n) => n.toString(16).padStart(2, '0');

function expect(tlv, tag) {
  if (tlv.tag !== tag) {
    throw new Error(`DER: expected tag 0x${hex2(tag)}, found 0x${hex2(tlv.tag)}`);
  }
}

function decodeOne(buf, tag) {
  const tlv = readTlv(buf, 0);
  if (tlv.end !== buf.length) throw new Error('DER: trailing data');
  expect(tlv, tag);
  return tlv;
}

function children(content) {
  const out = [];
  let pos = 0;
  while (pos < content.length) {
    const tlv = readTlv(content, pos);
    out.push(tlv);
    pos = tlv.end;
  }
  return out;
}

function oid(tlv) {
  expect(tlv, OID_TAG);
  return decodeOid(tlv.content);
}

function algorithmOid(tlv) {
  expect(tlv, SEQUENCE);
  const first = children(tlv.content)[0];
  if (!first) throw new Error('DER: empty AlgorithmIdentifier');
  return oid(first);
}

// SHA-2 digest under a digest AlgorithmIdentifier OID.
export function digestWith(alg, message) {
  const hash = SHA[alg];
  if (!hash) throw new Error(`unsupported digest algorithm: ${alg}`);
  return crypto.createHash(hash).update(message).digest();
}

// A CMS signature (RFC 5652 SignerInfo) with a certificate's key. A bare key
// algorithm (id-ecPublicKey, rsaEncryption) takes its hash from digestAlg.
export function verifyCmsSignature(cert, sigAlg, digestAlg, message, sig) {
  if (sigAlg === OID.ED25519) {
    let key;
    try {
      key = publicKeyOf(cert);
      if (key.asymmetricKeyType !== 'ed25519') throw new Error('not an Ed25519 key');
    } catch (e) {
      throw new Error(`Ed25519 key: ${e.message}`);
    }
    if (sig.length !== 64) throw new Error('malformed signature');
    if (!crypto.verify(null, message, key, sig)) throw new Error('signature verification failed');
    return;
  }
  if (sigAlg === RSA_ENCRYPTION || RSA[sigAlg]) {
    const hash = sigAlg === RSA_ENCRYPTION ? SHA[digestAlg] : RSA[sigAlg];
    if (!hash) throw new Error(`unsupported RSA digest algorithm: ${digestAlg}`);
    let ok = false;
    try {
      const key = publicKeyOf(cert);
      ok = key.asymmetricKeyType === 'rsa' && crypto.verify(hash, message, key, sig);
    } catch {
      ok = false;
    }
    if (!ok) throw new Error('signature verification failed');
    return;
  }
  let hash;
  if (ECDSA[sigAlg]) hash = ECDSA[sigAlg];
  else if (sigAlg === OID.EC_PUBLIC_KEY) hash = SHA[digestAlg];
  else throw new Error(`unsupported signature algorithm: ${sigAlg}`);
  if (cert.keyAlgOid !== OID.EC_PUBLIC_KEY) {
    throw new Error('signing certificate does not hold an EC key');
  }
  if (!hash) throw new Error(`unsupported digest algorithm: ${digestAlg}`);
  let ok = false;
  if ((cert.keyCurveOid === OID.P256 || cert.keyCurveOid === OID.P384) && isEcdsaSigDer(sig)) {
    try {
      ok = crypto.verify(hash, message, { key: publicKeyOf(cert), dsaEncoding: 'der' }, sig);
    } catch {
      ok = false;
    }
  }
  if (!ok) throw new Error('signature verification failed');
}

// YYYYMMDDHHMMSS[.fff]Z to epoch seconds, fractions dropped.
export function parseGeneralizedTime(raw) {
  const s = raw.toString('latin1');
  if (!/^[\x00-\x7f]*$/.test(s)) throw new Error('timestamp: genTime is not ASCII');
  const bad = () => new Error(`timestamp: unsupported genTime "${s}"`);
  if (!s.endsWith('Z')) throw bad();
  const whole = s.slice(0, -1).split('.')[0];
  if (!/^\d{14}$/.test(whole)) throw bad();
  const n = (a, b) => Number(whole.slice(a, b));
  const [y, mo, d, h, mi, se] = [n(0, 4), n(4, 6), n(6, 8), n(8, 10), n(10, 12), n(12, 14)];
  if (mo < 1 || mo > 12 || d < 1 || d > 31 || h > 23 || mi > 59 || se > 60) throw bad();
  return Math.floor(Date.UTC(y, mo - 1, d) / 1000) + h * 3600 + mi * 60 + se;
}

function parse(resp, signature) {
  // TimeStampResp ::= SEQUENCE { status PKIStatusInfo, timeStampToken ContentInfo }
  let top;
  try {
    top = decodeOne(resp, SEQUENCE);
  } catch (e) {
    throw new Error(`timestamp: ${e.message}`);
  }
  const parts = children(top.content);
  if (parts.length < 2) throw new Error('timestamp response carries no token');
  const code = children(parts[0].content)[0];
  if (!code) throw new Error('timestamp: empty status');
  expect(code, INTEGER);
  if (!(code.content.length === 1 && (code.content[0] === 0 || code.content[0] === 1))) {
    throw new Error('timestamp response status is not granted');
  }

  // ContentInfo ::= SEQUENCE { contentType, [0] EXPLICIT SignedData }
  const contentInfo = children(parts[1].content);
  if (contentInfo.length !== 2 || oid(contentInfo[0]) !== SIGNED_DATA) {
    throw new Error('timestamp token is not CMS SignedData');
  }
  const signedData = decodeOne(contentInfo[1].content, SEQUENCE);
  const fields = children(signedData.content);
  if (fields.length < 4) throw new Error('timestamp: truncated SignedData');

  // encapContentInfo ::= SEQUENCE { eContentType, [0] EXPLICIT OCTET STRING }
  const encap = children(fields[2].content);
  if (encap.length !== 2 || oid(encap[0]) !== TST_INFO) {
    throw new Error('timestamp token does not hold a TSTInfo');
  }
  const eContent = decodeOne(encap[1].content, OCTET_STRING).content;
  const embedded = [];
  let signerInfos = null;
  for (const f of fields.slice(3)) {
    if (f.tag === 0xa0) {
      for (const c of children(f.content)) {
        // CertificateChoices: only plain certificates are used.
        if (c.tag !== SEQUENCE) continue;
        try {
          embedded.push(parseCertificate(c.raw));
        } catch (e) {
          throw new Error(`timestamp certificate: ${e.message}`);
        }
      }
    } else if (f.tag === 0xa1) {
      continue;
    } else if (f.tag === SET) {
      signerInfos = f;
    } else {
      throw new Error('timestamp: unexpected SignedData field');
    }
  }
  if (!signerInfos) throw new Error('timestamp has no signer');
  const infos = children(signerInfos.content);
  if (infos.length !== 1) throw new Error('timestamp must have exactly one signer');
  const { signer, signedAttrs, digestAlg, sigAlg, sig } = parseSignerInfo(infos[0]);
  checkSignedAttrs(signedAttrs, digestAlg, eContent);
  const genTime = checkTstInfo(eContent, signature);
  // The signature covers the attributes as an explicit SET OF (RFC 5652 §5.4).
  const signed = Buffer.from(signedAttrs.raw);
  signed[0] = SET;
  return { genTime, signer, signedAttrs: signed, digestAlg, sigAlg, signature: sig, embedded };
}

function parseSignerInfo(info) {
  const f = children(info.content);
  if (f.length < 5) throw new Error('timestamp: truncated SignerInfo');
  let signer;
  if (f[1].tag === SEQUENCE) {
    const ias = children(f[1].content);
    if (ias.length !== 2) throw new Error('timestamp: bad issuerAndSerialNumber');
    expect(ias[1], INTEGER);
    signer = { issuer: ias[0].raw, serial: ias[1].content };
  } else if (f[1].tag === 0x80) {
    signer = { keyId: f[1].content };
  } else {
    throw new Error('timestamp: unsupported signer identifier');
  }
  const digestAlg = algorithmOid(f[2]);
  if (f[3].tag !== 0xa0) throw new Error('timestamp signer has no signed attributes');
  const sigAlg = algorithmOid(f[4]);
  const sig = f[5];
  if (!sig) throw new Error('timestamp: SignerInfo has no signature');
  expect(sig, OCTET_STRING);
  return { signer, signedAttrs: f[3], digestAlg, sigAlg, sig: sig.content };
}

// The signed attributes must name TSTInfo as the content type and carry the
// digest of the encapsulated TSTInfo, so the signature covers the time.
function checkSignedAttrs(attrs, digestAlg, eContent) {
  let contentTypeOk = false;
  let digestOk = false;
  for (const attr of children(attrs.content)) {
    const parts = children(attr.content);
    if (parts.length !== 2) throw new Error('timestamp: malformed signed attribute');
    const kind = oid(parts[0]);
    const values = children(parts[1].content);
    if (kind === CONTENT_TYPE) {
      contentTypeOk = values.length === 1 && oid(values[0]) === TST_INFO;
    } else if (kind === MESSAGE_DIGEST) {
      const expected = digestWith(digestAlg, eContent);
      digestOk =
        values.length === 1 && values[0].tag === OCTET_STRING && values[0].content.equals(expected);
    }
  }
  if (!contentTypeOk) throw new Error('timestamp signed attributes do not name TSTInfo');
  if (!digestOk) throw new Error('timestamp message digest does not match its TSTInfo');
}

// TSTInfo: the message imprint must be the hash of `signature`. Returns
// genTime in epoch seconds.
function checkTstInfo(der, signature) {
  const info = decodeOne(der, SEQUENCE);
  const f = children(info.content);
  if (f.length < 5) throw new Error('timestamp: truncated TSTInfo');
  const imprint = children(f[2].content);
  if (imprint.length !== 2) throw new Error('timestamp: malformed message imprint');
  const expected = digestWith(algorithmOid(imprint[0]), signature);
  expect(imprint[1], OCTET_STRING);
  if (!imprint[1].content.equals(expected)) {
    throw new Error('timestamp does not cover this signature');
  }
  expect(f[4], GENERALIZED_TIME);
  return parseGeneralizedTime(f[4].content);
}

const trimZeros = (b) => {
  let i = 0;
  while (i < b.length && b[i] === 0) i++;
  return b.subarray(i);
};

function matchesSigner(cert, id) {
  if (id.issuer) {
    return cert.issuerRaw.equals(id.issuer) && trimZeros(cert.serial).equals(trimZeros(id.serial));
  }
  const ski = extension(cert, SUBJECT_KEY_ID);
  if (!ski) return false;
  try {
    return decodeOne(ski.value, OCTET_STRING).content.equals(id.keyId);
  } catch {
    return false;
  }
}

function checkValidAt(path, at) {
  for (const cert of path) {
    if (at < cert.notBefore || at > cert.notAfter) {
      throw new Error(
        `certificate "${cert.subject}" is not valid at ${at} (valid ${cert.notBefore} to ${cert.notAfter})`,
      );
    }
  }
}

function checkTimestampingLeaf(cert) {
  const ext = extension(cert, OID.EXT_KEY_USAGE);
  if (!ext) throw new Error('timestamp signer certificate has no extended key usage');
  let ekus;
  try {
    ekus = extKeyUsages(ext.value);
  } catch (e) {
    throw new Error(`extended key usage: ${e.message}`);
  }
  if (!ekus.includes(EKU_TIME_STAMPING)) {
    throw new Error('timestamp signer certificate is not issued for timestamping');
  }
}

// The signer certificate (embedded in the token or listed by the authority)
// must chain to the authority's anchor through the authority's own
// certificates, be valid at genTime, and be issued for timestamping.
function verifyWith(token, authority) {
  const anchor = authority.certs[authority.certs.length - 1];
  if (!anchor) throw new Error('timestamp authority has no certificates');
  const signer = [...token.embedded, ...authority.certs].find((c) =>
    matchesSigner(c, token.signer),
  );
  if (!signer) throw new Error('timestamp signer certificate not found');
  const noChain = () =>
    new Error(`timestamp signer does not chain to the authority "${anchor.subject}"`);
  const path = [signer];
  while (!path[path.length - 1].der.equals(anchor.der)) {
    if (path.length > authority.certs.length) throw noChain();
    const cur = path[path.length - 1];
    const issuer = authority.certs.find((ca) => {
      try {
        verifySignedBy(cur, ca);
        return true;
      } catch {
        return false;
      }
    });
    if (!issuer) throw noChain();
    path.push(issuer);
  }
  for (let i = 1; i < path.length; i++) checkIssuer(path[i], i - 1);
  try {
    checkValidAt(path, token.genTime);
  } catch (e) {
    throw new Error(`timestamp: ${e.message}`);
  }
  checkTimestampingLeaf(signer);
  if (!authority.valid.contains(token.genTime)) {
    throw new Error(
      `timestamp authority "${anchor.subject}" was outside its validity window at ${token.genTime}`,
    );
  }
  try {
    verifyCmsSignature(signer, token.sigAlg, token.digestAlg, token.signedAttrs, token.signature);
  } catch (e) {
    throw new Error(`timestamp: ${e.message}`);
  }
}

// Verify one DER TimeStampResp over `signature` (the signature bytes the
// timestamp covers) against `authorities`. The first authority whose chain
// holds wins. Returns { time, authority }.
export function verifyTimestamp(resp, signature, authorities) {
  const token = parse(resp, signature);
  let firstError = null;
  for (const authority of authorities) {
    try {
      verifyWith(token, authority);
      return {
        time: token.genTime,
        authority: authority.certs[authority.certs.length - 1].subject,
      };
    } catch (e) {
      firstError ??= e;
    }
  }
  throw firstError ?? new Error('no trusted timestamp authority');
}
