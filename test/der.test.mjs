import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  basicConstraints,
  decodeOid,
  decodeOne,
  decodeTime,
  extKeyUsages,
  keyUsageHas,
  nameToString,
  parseCertificate,
  pemBodies,
  readTlv,
  sanIdentity,
  utf8String,
} from '../src/der.mjs';
import { window, windowFromJson } from '../src/trustroot.mjs';
import { b64decode, formatIso8601, joinRaw, parseIso8601 } from '../src/util.mjs';
import {
  bool,
  ext,
  genTime,
  int,
  name,
  oid,
  printable,
  seq,
  set,
  tlv,
  utf8,
} from './x509-build.mjs';

const FIXTURES = path.join(path.dirname(fileURLToPath(import.meta.url)), 'fixtures', 'trust-roots');

test('readTlv handles short and long definite lengths', () => {
  const short = tlv(0x04, Buffer.alloc(5));
  assert.equal(readTlv(short).content.length, 5);
  const long = tlv(0x04, Buffer.alloc(300));
  assert.deepEqual([...long.subarray(0, 4)], [0x04, 0x82, 0x01, 0x2c]);
  assert.equal(readTlv(long).content.length, 300);
  assert.throws(() => readTlv(long.subarray(0, 100)), /truncated/);
  assert.throws(() => decodeOne(Buffer.concat([short, short])), /trailing/);
});

test('OIDs decode, including multi-byte arcs and the first-arc rules', () => {
  for (const o of [
    '1.3.6.1.4.1.57264.1.8',
    '2.5.29.37.0',
    '1.2.840.10045.3.1.7',
    '0.9.2342.19200300.100.1.25',
    '2.999.3',
  ]) {
    assert.equal(decodeOid(readTlv(oid(o)).content), o);
  }
});

test('UTCTime and GeneralizedTime decode to epoch seconds', () => {
  const utc = (s) => tlv(0x17, Buffer.from(s));
  assert.equal(decodeTime(readTlv(utc('700101000000Z'))), 0);
  assert.equal(
    decodeTime(readTlv(utc('491231235959Z'))),
    Date.UTC(2049, 11, 31, 23, 59, 59) / 1000,
  );
  assert.equal(decodeTime(readTlv(utc('500101000000Z'))), Date.UTC(1950, 0, 1) / 1000);
  assert.equal(decodeTime(readTlv(genTime(4102444800))), 4102444800);
  assert.throws(() => decodeTime(readTlv(utc('7001010000Z'))), /bad time/);
});

test('names print as RFC 4514, last RDN first, escaped like the Rust verifier', () => {
  const n = (...pairs) => nameToString(readTlv(name(pairs)));
  assert.equal(
    n(['2.5.4.10', 'sigstore.dev'], ['2.5.4.3', 'sigstore']),
    'CN=sigstore,O=sigstore.dev',
  );
  assert.equal(n(['2.5.4.3', 'a,b+c"d']), 'CN=a\\,b\\+c\\"d');
  assert.equal(n(['2.5.4.3', '#lead and trail ']), 'CN=\\#lead and trail\\ ');
  assert.equal(n(['2.5.4.3', ' x']), 'CN=\\ x');
  assert.equal(n(['2.5.4.3', 'tab\there']), 'CN=tab\\09here');
  assert.equal(n(['1.2.840.113549.1.9.1', 'a@b.c']), 'EMAIL=a@b.c');
  // An attribute without a known short name prints as <oid>=#<DER hex>.
  assert.equal(n(['1.2.3.4', 'x']), '1.2.3.4=#0c0178');
  // A multi-valued RDN joins its attributes with '+'.
  const multi = seq(set(seq(oid('2.5.4.3'), utf8('a')), seq(oid('2.5.4.11'), printable('b'))));
  assert.equal(nameToString(readTlv(multi)), 'CN=a+OU=b');
});

test('extensions: SAN, Fulcio issuer, basicConstraints, keyUsage, extendedKeyUsage', () => {
  assert.equal(sanIdentity(ext.sanEmail('alice@acme.test')[1]), 'alice@acme.test');
  assert.equal(sanIdentity(ext.sanUri('https://github.com/a/b')[1]), 'https://github.com/a/b');
  // A DNS name ([2]) is not an identity.
  assert.equal(sanIdentity(seq(tlv(0x82, Buffer.from('example.com')))), null);
  assert.equal(utf8String(ext.fulcioIssuer('https://issuer')[1]), 'https://issuer');
  assert.deepEqual(basicConstraints(ext.basicConstraints(true, 0)[1]), { ca: true, pathLen: 0 });
  assert.deepEqual(basicConstraints(ext.basicConstraints(false)[1]), { ca: false, pathLen: null });
  assert.deepEqual(basicConstraints(seq(bool(true), int(300))), { ca: true, pathLen: 300 });
  const ku = ext.keyUsage(0, 5)[1];
  assert.ok(keyUsageHas(ku, 0));
  assert.ok(keyUsageHas(ku, 5));
  assert.ok(!keyUsageHas(ku, 6));
  assert.ok(!keyUsageHas(ext.keyUsage(0)[1], 5));
  assert.deepEqual(extKeyUsages(ext.extKeyUsage('1.3.6.1.5.5.7.3.3')[1]), ['1.3.6.1.5.5.7.3.3']);
});

test('parseCertificate reads a fixture leaf: names, validity, key, identity extensions', () => {
  const sidecar = JSON.parse(
    fs.readFileSync(path.join(FIXTURES, 'artifacts', 'prod-signed.txt.psig.json'), 'utf8'),
  );
  const leaf = parseCertificate(Buffer.from(sidecar.signer.certChain[0], 'base64'));
  assert.equal(leaf.subject, 'CN=sigstore-intermediate');
  assert.equal(leaf.issuer, 'CN=acme prod fulcio,O=promptsign tests');
  assert.equal(leaf.keyAlgOid, '1.3.101.112');
  assert.equal(leaf.sigAlgOid, '1.2.840.10045.4.3.2');
  assert.ok(leaf.notBefore < sidecar.transparency.integratedTime);
  assert.ok(sidecar.transparency.integratedTime < leaf.notAfter);
  const san = leaf.extensions.find((e) => e.oid === '2.5.29.17');
  assert.equal(sanIdentity(san.value), 'alice@acme.test');
});

test('pemBodies decodes every block of a label, oldest first', () => {
  const pem = fs.readFileSync(path.join(FIXTURES, 'public', 'fulcio.pem'), 'utf8');
  const certs = pemBodies(pem, 'CERTIFICATE').map(parseCertificate);
  assert.ok(certs.length >= 1);
  assert.ok(certs.some((c) => c.subject === 'CN=sigstore,O=sigstore.dev'));
  assert.deepEqual(pemBodies(pem, 'PUBLIC KEY'), []);
});

test('validFor windows are [start, end), open on a missing side', () => {
  const w = window(100, 200);
  assert.ok(!w.contains(99));
  assert.ok(w.contains(100));
  assert.ok(w.contains(199));
  assert.ok(!w.contains(200));
  assert.ok(window(null, 200).contains(-1e12));
  assert.ok(window(100, null).contains(1e12));
  assert.ok(window().contains(0));
});

test('validFor JSON: absent sides are open, bad times are errors', () => {
  const w = windowFromJson({ start: '2025-01-01T00:00:00Z', end: '2026-07-01T00:00:00Z' });
  assert.equal(w.start, 1735689600);
  assert.equal(w.end, 1782864000);
  assert.ok(!w.contains(1782864000));
  assert.deepEqual([windowFromJson(undefined).start, windowFromJson(null).end], [null, null]);
  assert.equal(windowFromJson({ start: '2025-01-01T00:00:00Z' }).end, null);
  assert.throws(
    () => windowFromJson({ start: 'yesterday' }),
    /validFor\.start is not an RFC 3339 time: "yesterday"/,
  );
  assert.throws(() => windowFromJson({ end: 5 }), /validFor\.end is not an RFC 3339 time: 5/);
});

test('RFC 3339 parse and format round-trip, with the Rust parser leniency', () => {
  assert.equal(parseIso8601('1970-01-01T00:00:00Z'), 0);
  assert.equal(parseIso8601('2024-02-29T12:00:00Z'), 19782 * 86400 + 43200);
  assert.equal(parseIso8601('2024-01-01T00:00:00.500Z'), 19723 * 86400);
  assert.equal(parseIso8601('2024-01-01T00:00Z'), 19723 * 86400);
  assert.equal(parseIso8601('not-a-date'), null);
  assert.equal(parseIso8601('2024-13-01T00:00:00Z'), null);
  for (const t of [0, 1735689600, 1790834400, 4291747200, -86400]) {
    assert.equal(parseIso8601(formatIso8601(t)), t);
  }
  assert.equal(formatIso8601(1790834400), '2026-10-01T06:00:00Z');
});

test('strict base64 and Rust-style path joins', () => {
  assert.deepEqual([...b64decode('AAEC')], [0, 1, 2]);
  assert.equal(b64decode('AAE'), null);
  assert.equal(b64decode('AA=C'), null);
  assert.equal(b64decode('AB=='), null); // stray trailing bits
  assert.equal(b64decode(5), null);
  const sep = path.sep;
  assert.equal(joinRaw('C:/x', 'trust', 'roots'), `C:/x${sep}trust${sep}roots`);
  assert.equal(joinRaw('/home/u/', 'trust'), '/home/u/trust');
});
