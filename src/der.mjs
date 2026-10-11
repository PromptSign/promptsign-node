// A small DER reader: just enough ASN.1 to take an X.509 certificate apart
// (spec/05 §2): names, validity, the key, and the extensions keyless and
// chain verification read (SAN, Fulcio issuer, basicConstraints, keyUsage,
// extendedKeyUsage). node:crypto verifies the signatures.

export const TAG = {
  BOOLEAN: 0x01,
  INTEGER: 0x02,
  BIT_STRING: 0x03,
  OCTET_STRING: 0x04,
  OID: 0x06,
  UTF8_STRING: 0x0c,
  PRINTABLE_STRING: 0x13,
  TELETEX_STRING: 0x14,
  IA5_STRING: 0x16,
  UTC_TIME: 0x17,
  GENERALIZED_TIME: 0x18,
  SEQUENCE: 0x30,
  SET: 0x31,
};

export const OID = {
  SAN: '2.5.29.17',
  BASIC_CONSTRAINTS: '2.5.29.19',
  KEY_USAGE: '2.5.29.15',
  EXT_KEY_USAGE: '2.5.29.37',
  EKU_CODE_SIGNING: '1.3.6.1.5.5.7.3.3',
  EKU_ANY: '2.5.29.37.0',
  FULCIO_ISSUER_V2: '1.3.6.1.4.1.57264.1.8',
  FULCIO_ISSUER_V1: '1.3.6.1.4.1.57264.1.1',
  ED25519: '1.3.101.112',
  EC_PUBLIC_KEY: '1.2.840.10045.2.1',
  P256: '1.2.840.10045.3.1.7',
  P384: '1.3.132.0.34',
  ECDSA_SHA256: '1.2.840.10045.4.3.2',
  ECDSA_SHA384: '1.2.840.10045.4.3.3',
  RSA_SHA256: '1.2.840.113549.1.1.11',
  RSA_SHA384: '1.2.840.113549.1.1.12',
  RSA_SHA512: '1.2.840.113549.1.1.13',
};

// One TLV at `pos`: { tag, content, raw, end }. Only low tag numbers and
// definite lengths, which is all DER allows for what we read.
export function readTlv(buf, pos = 0) {
  if (pos + 2 > buf.length) throw new Error('DER: truncated');
  const tag = buf[pos];
  if ((tag & 0x1f) === 0x1f) throw new Error('DER: unsupported tag');
  let len = buf[pos + 1];
  let start = pos + 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4 || start + n > buf.length) throw new Error('DER: bad length');
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + buf[start + i];
    start += n;
  }
  const end = start + len;
  if (end > buf.length) throw new Error('DER: truncated');
  return { tag, content: buf.subarray(start, end), raw: buf.subarray(pos, end), end };
}

// Exactly one TLV filling `buf`, optionally of the expected tag.
export function decodeOne(buf, tag) {
  const tlv = readTlv(buf, 0);
  if (tlv.end !== buf.length) throw new Error('DER: trailing data');
  if (tag !== undefined && tlv.tag !== tag) throw new Error('DER: unexpected tag');
  return tlv;
}

// The TLVs inside a constructed value's content.
export function children(content) {
  const out = [];
  let pos = 0;
  while (pos < content.length) {
    const tlv = readTlv(content, pos);
    out.push(tlv);
    pos = tlv.end;
  }
  return out;
}

export function decodeOid(content) {
  if (content.length === 0) throw new Error('DER: empty OID');
  const arcs = [];
  let v = 0;
  for (let i = 0; i < content.length; i++) {
    v = v * 128 + (content[i] & 0x7f);
    if (!(content[i] & 0x80)) {
      arcs.push(v);
      v = 0;
    } else if (i === content.length - 1) {
      throw new Error('DER: truncated OID');
    }
  }
  const first = arcs[0] < 40 ? 0 : arcs[0] < 80 ? 1 : 2;
  return [first, arcs[0] - first * 40, ...arcs.slice(1)].join('.');
}

// UTCTime (YYMMDDHHMMSSZ) or GeneralizedTime (YYYYMMDDHHMMSSZ) to epoch seconds.
export function decodeTime(tlv) {
  const s = tlv.content.toString('latin1');
  const m =
    tlv.tag === TAG.UTC_TIME
      ? /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(s)
      : tlv.tag === TAG.GENERALIZED_TIME
        ? /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(s)
        : null;
  if (!m) throw new Error('DER: bad time');
  let year = Number(m[1]);
  if (tlv.tag === TAG.UTC_TIME) year += year >= 50 ? 1900 : 2000;
  const ms = Date.UTC(
    year,
    Number(m[2]) - 1,
    Number(m[3]),
    Number(m[4]),
    Number(m[5]),
    Number(m[6]),
  );
  return Math.floor(ms / 1000);
}

function decodeString(tlv) {
  switch (tlv.tag) {
    case TAG.UTF8_STRING:
      return tlv.content.toString('utf8');
    case TAG.PRINTABLE_STRING:
    case TAG.IA5_STRING:
    case TAG.TELETEX_STRING:
      return tlv.content.toString('latin1');
    default:
      return null;
  }
}

// Attribute short names as the Rust verifier prints them (x509-cert picks
// the shortest name const-oid knows, upper-cased).
const ATTR_NAMES = {
  '2.5.4.3': 'CN',
  '2.5.4.4': 'SN',
  '2.5.4.5': 'SERIALNUMBER',
  '2.5.4.6': 'C',
  '2.5.4.7': 'L',
  '2.5.4.8': 'ST',
  '2.5.4.9': 'STREET',
  '2.5.4.10': 'O',
  '2.5.4.11': 'OU',
  '2.5.4.12': 'TITLE',
  '2.5.4.13': 'DESCRIPTION',
  '2.5.4.15': 'BUSINESSCATEGORY',
  '2.5.4.17': 'POSTALCODE',
  '2.5.4.41': 'NAME',
  '2.5.4.42': 'GIVENNAME',
  '2.5.4.43': 'INITIALS',
  '2.5.4.44': 'GENERATIONQUALIFIER',
  '2.5.4.46': 'DNQUALIFIER',
  '2.5.4.65': 'PSEUDONYM',
  '0.9.2342.19200300.100.1.1': 'UID',
  '0.9.2342.19200300.100.1.25': 'DC',
  '1.2.840.113549.1.9.1': 'EMAIL',
};

function escapeValue(val) {
  const chars = [...val];
  let out = '';
  chars.forEach((c, i) => {
    if (c === '#' && i === 0) out += '\\#';
    else if (c === ' ' && (i === 0 || i === chars.length - 1)) out += '\\ ';
    else if ('"+,;<>\\'.includes(c)) out += '\\' + c;
    else if (c <= '\x1f' || c === '\x7f')
      out += '\\' + c.charCodeAt(0).toString(16).padStart(2, '0');
    else out += c;
  });
  return out;
}

// A Name as an RFC 4514 string: last RDN first, no spaces after commas.
export function nameToString(nameTlv) {
  const rdns = children(nameTlv.content).map((set) =>
    children(set.content)
      .map((atv) => {
        const [oidTlv, value] = children(atv.content);
        const oid = decodeOid(oidTlv.content);
        const str = decodeString(value);
        if (ATTR_NAMES[oid] && str !== null) return `${ATTR_NAMES[oid]}=${escapeValue(str)}`;
        return `${oid}=#${value.raw.toString('hex')}`;
      })
      .join('+'),
  );
  return rdns.reverse().join(',');
}

function algorithm(tlv) {
  const [oid, params] = children(tlv.content);
  return { oid: decodeOid(oid.content), params };
}

// The parts of an X.509 certificate the verifiers use. Throws on anything
// that is not a well-formed v1-v3 certificate.
export function parseCertificate(der) {
  const cert = decodeOne(der, TAG.SEQUENCE);
  const [tbs, sigAlg, sigBits] = children(cert.content);
  if (!tbs || tbs.tag !== TAG.SEQUENCE || !sigAlg || sigBits?.tag !== TAG.BIT_STRING) {
    throw new Error('DER: not a certificate');
  }
  const f = children(tbs.content);
  let i = f[0]?.tag === 0xa0 ? 1 : 0;
  const [, , issuer, validity, subject, spki] = f.slice(i, i + 6);
  if (!spki || spki.tag !== TAG.SEQUENCE || validity.tag !== TAG.SEQUENCE) {
    throw new Error('DER: not a certificate');
  }
  i += 6;
  const [notBefore, notAfter] = children(validity.content);
  const [spkiAlg] = children(spki.content);
  const keyAlg = algorithm(spkiAlg);
  const extensions = [];
  for (const t of f.slice(i)) {
    if (t.tag !== 0xa3) continue;
    for (const ext of children(decodeOne(t.content, TAG.SEQUENCE).content)) {
      const parts = children(ext.content);
      const value = parts[parts.length - 1];
      if (parts.length < 2 || value.tag !== TAG.OCTET_STRING) throw new Error('DER: bad extension');
      extensions.push({ oid: decodeOid(parts[0].content), value: value.content });
    }
  }
  return {
    der: Buffer.from(der),
    tbs: tbs.raw,
    sigAlgOid: algorithm(sigAlg).oid,
    // First content byte of a BIT STRING counts its unused bits.
    sigUnusedBits: sigBits.content[0],
    signature: sigBits.content.subarray(1),
    issuerRaw: issuer.raw,
    subjectRaw: subject.raw,
    issuer: nameToString(issuer),
    subject: nameToString(subject),
    notBefore: decodeTime(notBefore),
    notAfter: decodeTime(notAfter),
    spkiDer: spki.raw,
    keyAlgOid: keyAlg.oid,
    keyCurveOid: keyAlg.params?.tag === TAG.OID ? decodeOid(keyAlg.params.content) : null,
    extensions,
  };
}

export function extension(cert, oid) {
  return cert.extensions.find((e) => e.oid === oid);
}

// SubjectAltName: the first rfc822Name ([1]) or uniformResourceIdentifier
// ([6]), or null.
export function sanIdentity(value) {
  for (const gn of children(decodeOne(value, TAG.SEQUENCE).content)) {
    if (gn.tag === 0x81 || gn.tag === 0x86) return gn.content.toString('latin1');
  }
  return null;
}

export function utf8String(value) {
  return decodeOne(value, TAG.UTF8_STRING).content.toString('utf8');
}

// basicConstraints: { ca, pathLen } (pathLen null when absent).
export function basicConstraints(value) {
  const parts = children(decodeOne(value, TAG.SEQUENCE).content);
  let ca = false;
  let pathLen = null;
  for (const p of parts) {
    if (p.tag === TAG.BOOLEAN) ca = p.content[0] !== 0;
    else if (p.tag === TAG.INTEGER) pathLen = p.content.reduce((n, b) => n * 256 + b, 0);
    else throw new Error('DER: bad basic constraints');
  }
  return { ca, pathLen };
}

// keyUsage bit n (0 = digitalSignature, 5 = keyCertSign), counted from the
// most significant bit of the first byte.
export function keyUsageHas(value, bit) {
  const bits = decodeOne(value, TAG.BIT_STRING).content.subarray(1);
  const byte = bits[bit >> 3];
  return byte !== undefined && (byte & (0x80 >> (bit & 7))) !== 0;
}

export function extKeyUsages(value) {
  return children(decodeOne(value, TAG.SEQUENCE).content).map((t) => decodeOid(t.content));
}

// The bodies of every PEM block with this label, decoded.
export function pemBodies(text, label) {
  const begin = `-----BEGIN ${label}-----`;
  const end = `-----END ${label}-----`;
  const out = [];
  let rest = text;
  for (;;) {
    const s = rest.indexOf(begin);
    if (s === -1) break;
    const after = rest.slice(s + begin.length);
    const stop = after.indexOf(end);
    if (stop === -1) throw new Error(`missing ${end}`);
    out.push(Buffer.from(after.slice(0, stop).replace(/\s+/g, ''), 'base64'));
    rest = after.slice(stop + end.length);
  }
  return out;
}

// Whether a DER ECDSA signature is SEQUENCE { INTEGER r, INTEGER s }.
export function isEcdsaSigDer(sig) {
  try {
    const parts = children(decodeOne(sig, TAG.SEQUENCE).content);
    return parts.length === 2 && parts.every((p) => p.tag === TAG.INTEGER && p.content.length > 0);
  } catch {
    return false;
  }
}
