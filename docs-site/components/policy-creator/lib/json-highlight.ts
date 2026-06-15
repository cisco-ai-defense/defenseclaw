// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Tiny tokenizer for JSON, used by the CodeEditor overlay so the
// operator's hand-written test inputs in the Live Test pane are
// readable. Same zero-dep philosophy as lib/rego-highlight.ts.
//
// Highlighting is presentation-only; the authoritative parse happens
// via JSON.parse() before we feed the input to OPA.
//
// Tokens are intentionally coarse (no key-vs-value distinction in
// strings) — sufficient to make a 200-line JSON doc scannable
// without dragging in a real parser.

import { escapeHtml } from './rego-highlight';

export type JsonTokenKind =
  | 'string'
  | 'number'
  | 'literal'
  | 'punctuation'
  | 'plain';

export interface JsonToken {
  kind: JsonTokenKind;
  text: string;
}

const LITERALS = new Set(['true', 'false', 'null']);

export function tokenizeJson(source: string): JsonToken[] {
  const out: JsonToken[] = [];
  let i = 0;
  const n = source.length;

  while (i < n) {
    const ch = source[i];

    // Double-quoted string with escape handling. Unterminated strings
    // (operator typing mid-token) are still emitted so the highlight
    // doesn't flicker between glyphs.
    if (ch === '"') {
      let j = i + 1;
      while (j < n) {
        if (source[j] === '\\' && j + 1 < n) {
          j += 2;
          continue;
        }
        if (source[j] === '"' || source[j] === '\n') break;
        j += 1;
      }
      if (j < n && source[j] === '"') j += 1;
      out.push({ kind: 'string', text: source.slice(i, j) });
      i = j;
      continue;
    }

    // Number: -? digits, optional fraction, optional exponent. We
    // don't validate strictly — the JSON.parse step does that — but
    // we cover enough of the grammar that valid inputs always pick
    // up the number color.
    if (ch === '-' || /[0-9]/.test(ch)) {
      let j = i;
      if (source[j] === '-') j += 1;
      while (j < n && /[0-9]/.test(source[j])) j += 1;
      if (j < n && source[j] === '.') {
        j += 1;
        while (j < n && /[0-9]/.test(source[j])) j += 1;
      }
      if (j < n && (source[j] === 'e' || source[j] === 'E')) {
        j += 1;
        if (j < n && (source[j] === '+' || source[j] === '-')) j += 1;
        while (j < n && /[0-9]/.test(source[j])) j += 1;
      }
      // If we only consumed "-" with nothing after, treat it as
      // punctuation/plain — the user is mid-typing.
      if (j === i + 1 && source[i] === '-') {
        out.push({ kind: 'plain', text: ch });
        i += 1;
        continue;
      }
      out.push({ kind: 'number', text: source.slice(i, j) });
      i = j;
      continue;
    }

    // Literals: true / false / null
    if (/[a-z]/.test(ch)) {
      let j = i + 1;
      while (j < n && /[a-z]/.test(source[j])) j += 1;
      const word = source.slice(i, j);
      if (LITERALS.has(word)) {
        out.push({ kind: 'literal', text: word });
      } else {
        out.push({ kind: 'plain', text: word });
      }
      i = j;
      continue;
    }

    if ('{}[],:'.includes(ch)) {
      out.push({ kind: 'punctuation', text: ch });
      i += 1;
      continue;
    }

    out.push({ kind: 'plain', text: ch });
    i += 1;
  }

  return out;
}

const TOKEN_CLASS: Record<JsonTokenKind, string> = {
  string: 'text-emerald-700 dark:text-emerald-400',
  number: 'text-amber-700 dark:text-amber-400',
  literal: 'text-purple-700 dark:text-purple-400 font-semibold',
  punctuation: 'text-fd-muted-foreground',
  plain: '',
};

export function highlightJsonToHtml(source: string): string {
  const tokens = tokenizeJson(source);
  const parts: string[] = [];
  for (const t of tokens) {
    const cls = TOKEN_CLASS[t.kind];
    const safe = escapeHtml(t.text);
    if (cls) parts.push(`<span class="${cls}">${safe}</span>`);
    else parts.push(safe);
  }
  if (!source.endsWith('\n')) parts.push('\n');
  return parts.join('');
}
