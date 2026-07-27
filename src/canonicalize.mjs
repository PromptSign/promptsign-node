// Canonicalization of instruction files per spec/02-canonicalization.md.
// Only .md/.markdown files are canonicalized; everything else is hashed as raw bytes.

import { createHash } from 'node:crypto';

export class CanonError extends Error {
  constructor(message, line) {
    super(line ? `${message} (line ${line})` : message);
    this.line = line;
  }
}

export function sha256(buf) {
  return createHash('sha256').update(buf).digest('hex');
}

export function isMarkdown(relPath) {
  return /\.(md|markdown)$/i.test(relPath);
}

// Always rejected, even inside code fences: Unicode Tags block (invisible
// instruction smuggling), bidi controls (Trojan Source), directional marks.
const ALWAYS_BAD =
  /[\u{E0000}-\u{E007F}\u{202A}-\u{202E}\u{2066}-\u{2069}\u{200E}\u{200F}\u{061C}]/u;
// Rejected outside code fences: zero-width space, word joiner, interior BOM.
const ZERO_WIDTH = /[\u{200B}\u{2060}\u{FEFF}]/u;
// ZWNJ/ZWJ are legitimate in Persian/Arabic text and emoji sequences; they are
// rejected only when surrounded by ASCII, where their only purpose is smuggling.
const JOINERS = /[\u{200C}\u{200D}]/gu;

function checkInvisible(lines) {
  let inFence = false;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const m = ALWAYS_BAD.exec(line);
    if (m) {
      throw new CanonError(
        `disallowed invisible/bidi character U+${m[0].codePointAt(0).toString(16).toUpperCase().padStart(4, '0')}`,
        i + 1,
      );
    }
    if (/^\s*(```|~~~)/.test(line)) {
      inFence = !inFence;
      continue;
    }
    if (inFence) continue;
    const z = ZERO_WIDTH.exec(line);
    if (z) {
      throw new CanonError(
        `disallowed zero-width character U+${z[0].codePointAt(0).toString(16).toUpperCase().padStart(4, '0')} outside code fence`,
        i + 1,
      );
    }
    for (const j of line.matchAll(JOINERS)) {
      const prev = j.index > 0 ? line.codePointAt(j.index - 1) : null;
      const nextIdx = j.index + j[0].length;
      const next = nextIdx < line.length ? line.codePointAt(nextIdx) : null;
      const asciiPrev = prev === null || prev <= 0x7f;
      const asciiNext = next === null || next <= 0x7f;
      if (asciiPrev && asciiNext) {
        throw new CanonError(
          `zero-width joiner U+${j[0].codePointAt(0).toString(16).toUpperCase()} in ASCII context`,
          i + 1,
        );
      }
    }
  }
}

// Remove an `x-promptsign:` mapping from YAML frontmatter (embedded-signature
// fallback carriage) so the signature is not part of the signed content.
export function stripSignatureBlock(text) {
  if (!text.startsWith('---\n')) return text;
  const end = text.indexOf('\n---', 3);
  if (end === -1) return text;
  const fmLines = text.slice(4, end).split('\n');
  const kept = [];
  let skipping = false;
  for (const line of fmLines) {
    if (/^x-promptsign:/.test(line)) {
      skipping = true;
      continue;
    }
    if (skipping && /^[ \t]/.test(line)) continue;
    skipping = false;
    kept.push(line);
  }
  return '---\n' + kept.join('\n') + text.slice(end);
}

// Canonical form: strict UTF-8, no BOM, LF endings, NFC, no trailing
// whitespace, exactly one trailing newline, signature block excised.
export function canonicalizeMarkdown(buf) {
  let text;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(buf);
  } catch {
    throw new CanonError('invalid UTF-8');
  }
  if (text.startsWith('\u{FEFF}')) text = text.slice(1);
  text = text.replace(/\r\n?/g, '\n');
  text = text.normalize('NFC');
  text = stripSignatureBlock(text);
  const lines = text.split('\n').map((l) => l.replace(/[ \t]+$/, ''));
  while (lines.length && lines[lines.length - 1] === '') lines.pop();
  checkInvisible(lines);
  return lines.join('\n') + '\n';
}

// Digest used in manifests: canonical form for Markdown, raw bytes otherwise.
// Executables are ALWAYS raw bytes — never normalize code you will run.
export function digestFile(buf, relPath, role) {
  if (role !== 'executable' && isMarkdown(relPath)) {
    return sha256(Buffer.from(canonicalizeMarkdown(buf), 'utf8'));
  }
  return sha256(buf);
}
