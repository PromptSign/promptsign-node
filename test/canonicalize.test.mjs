import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  canonicalizeMarkdown,
  sha256,
  CanonError,
  stripSignatureBlock,
} from '../src/canonicalize.mjs';

const hash = (s) => sha256(Buffer.from(canonicalizeMarkdown(Buffer.from(s, 'utf8')), 'utf8'));

test('CRLF, CR and LF line endings hash identically', () => {
  assert.equal(hash('# Title\r\nbody\r\n'), hash('# Title\nbody\n'));
  assert.equal(hash('# Title\rbody\r'), hash('# Title\nbody\n'));
});

test('leading BOM is stripped', () => {
  assert.equal(hash('﻿# Title\n'), hash('# Title\n'));
});

test('NFC and NFD forms hash identically', () => {
  assert.equal(hash('café\n'), hash('café\n')); // é composed vs decomposed
});

test('trailing whitespace and trailing blank lines are normalized', () => {
  assert.equal(hash('line one  \t\nline two\n\n\n'), hash('line one\nline two\n'));
});

test('missing trailing newline is normalized', () => {
  assert.equal(hash('# Title'), hash('# Title\n'));
});

test('Unicode Tags-block characters are rejected even inside fences', () => {
  assert.throws(() => canonicalizeMarkdown(Buffer.from('hi \u{E0041}\u{E0042}\n')), CanonError);
  assert.throws(() => canonicalizeMarkdown(Buffer.from('```\nx \u{E0041}\n```\n')), CanonError);
});

test('bidi override controls are rejected', () => {
  assert.throws(() => canonicalizeMarkdown(Buffer.from('a‮b\n')), CanonError);
});

test('zero-width space rejected outside fences, allowed inside', () => {
  assert.throws(() => canonicalizeMarkdown(Buffer.from('a​b\n')), CanonError);
  assert.doesNotThrow(() => canonicalizeMarkdown(Buffer.from('```\na​b\n```\n')));
});

test('ZWJ allowed in emoji, rejected between ASCII', () => {
  assert.doesNotThrow(() => canonicalizeMarkdown(Buffer.from('family: \u{1F468}‍\u{1F469}\n')));
  assert.throws(() => canonicalizeMarkdown(Buffer.from('ad‍min\n')), CanonError);
});

test('invalid UTF-8 is rejected', () => {
  assert.throws(
    () => canonicalizeMarkdown(Buffer.from([0x23, 0x20, 0xff, 0xfe, 0x0a])),
    CanonError,
  );
});

test('x-promptsign frontmatter block is excluded from canonical form', () => {
  const unsigned = '---\nname: demo\n---\n\nbody\n';
  const signed = '---\nname: demo\nx-promptsign:\n  v: 1\n  sig: "abc"\n---\n\nbody\n';
  assert.equal(hash(signed), hash(unsigned));
});

test('stripSignatureBlock leaves files without frontmatter untouched', () => {
  assert.equal(stripSignatureBlock('# plain\n'), '# plain\n');
});
