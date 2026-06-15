// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Tiny tokenizer for OPA Rego, used by the in-browser Rego editor to
// render a syntax-highlighted overlay behind a transparent textarea.
//
// Why a homegrown 100-line tokenizer instead of CodeMirror or
// Monaco? Bundle size: those weigh 150–500 KB and pull in IO/worker
// machinery the operator never uses. Rego's grammar is small and
// stable enough that a single-pass regex pipeline produces a "good
// enough" highlight without a parser.
//
// We intentionally do NOT try to be semantically correct — this is a
// presentation-only highlighter. The authoritative parse happens
// server-side via `opa check` when the install script runs.

export type TokenKind =
  | 'comment'
  | 'string'
  | 'number'
  | 'keyword'
  | 'builtin'
  | 'operator'
  | 'punctuation'
  | 'identifier'
  | 'plain';

export interface RegoToken {
  kind: TokenKind;
  text: string;
}

const KEYWORDS = new Set([
  'package', 'import', 'as', 'with', 'default', 'else', 'every', 'some',
  'in', 'if', 'not', 'true', 'false', 'null', 'contains',
]);

// Subset of common OPA built-ins that show up in admission/guardrail
// rules. Not exhaustive — anything we don't classify as a builtin
// falls through to 'identifier', which is fine.
const BUILTINS = new Set([
  'input', 'data', 'count', 'sum', 'max', 'min', 'sort',
  'startswith', 'endswith', 'contains', 'lower', 'upper', 'split',
  'sprintf', 'concat', 'replace', 'trim', 'regex',
  'object', 'array', 'set', 'json', 'time',
]);

/** Tokenize a Rego source string. The result is a flat array; the
 *  consumer renders each token wrapped in a class-tagged <span>. */
export function tokenizeRego(source: string): RegoToken[] {
  const out: RegoToken[] = [];
  let i = 0;
  const n = source.length;

  function pushPlain(s: string) {
    if (!s) return;
    if (out.length && out[out.length - 1].kind === 'plain') {
      out[out.length - 1].text += s;
    } else {
      out.push({ kind: 'plain', text: s });
    }
  }

  while (i < n) {
    const ch = source[i];

    // Line comment: # to EOL
    if (ch === '#') {
      let j = i;
      while (j < n && source[j] !== '\n') j += 1;
      out.push({ kind: 'comment', text: source.slice(i, j) });
      i = j;
      continue;
    }

    // Backtick raw string
    if (ch === '`') {
      let j = i + 1;
      while (j < n && source[j] !== '`') j += 1;
      if (j < n) j += 1; // include closing backtick
      out.push({ kind: 'string', text: source.slice(i, j) });
      i = j;
      continue;
    }

    // Double-quoted string with escape support
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

    // Number (integer or float, optional sign handled by operator
    // tokenization, no exponent — Rego allows them but we keep this
    // simple)
    if (/[0-9]/.test(ch)) {
      let j = i + 1;
      while (j < n && /[0-9.]/.test(source[j])) j += 1;
      out.push({ kind: 'number', text: source.slice(i, j) });
      i = j;
      continue;
    }

    // Identifier / keyword / builtin
    if (/[A-Za-z_]/.test(ch)) {
      let j = i + 1;
      while (j < n && /[A-Za-z0-9_]/.test(source[j])) j += 1;
      const word = source.slice(i, j);
      if (KEYWORDS.has(word)) out.push({ kind: 'keyword', text: word });
      else if (BUILTINS.has(word)) out.push({ kind: 'builtin', text: word });
      else out.push({ kind: 'identifier', text: word });
      i = j;
      continue;
    }

    // Multi-char operators (try longest first)
    const two = source.slice(i, i + 2);
    if (two === ':=' || two === '==' || two === '!=' || two === '<=' || two === '>=') {
      out.push({ kind: 'operator', text: two });
      i += 2;
      continue;
    }

    // Single-char operators / punctuation
    if ('+-*/%<>=&|!'.includes(ch)) {
      out.push({ kind: 'operator', text: ch });
      i += 1;
      continue;
    }
    if ('{}[]().,;:'.includes(ch)) {
      out.push({ kind: 'punctuation', text: ch });
      i += 1;
      continue;
    }

    // Whitespace and unhandled characters fall through as plain.
    pushPlain(ch);
    i += 1;
  }

  return out;
}

/** HTML-escape a string for safe injection into the highlighter
 *  overlay. The overlay never receives user input directly — only
 *  pre-tokenized text — but we still escape because tokens preserve
 *  their original characters verbatim. */
export function escapeHtml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

const TOKEN_CLASS: Record<TokenKind, string> = {
  comment: 'text-fd-muted-foreground italic',
  string: 'text-emerald-700 dark:text-emerald-400',
  number: 'text-amber-700 dark:text-amber-400',
  keyword: 'text-purple-700 dark:text-purple-400 font-semibold',
  builtin: 'text-[var(--brand-cisco-strong,var(--brand-cisco))] dark:text-[var(--brand-cisco)] font-medium',
  operator: 'text-rose-700 dark:text-rose-400',
  punctuation: 'text-fd-muted-foreground',
  identifier: '',
  plain: '',
};

/** Render a Rego source as the inner HTML for the overlay <pre>. */
export function highlightRegoToHtml(source: string): string {
  const tokens = tokenizeRego(source);
  const parts: string[] = [];
  for (const t of tokens) {
    const cls = TOKEN_CLASS[t.kind];
    const safe = escapeHtml(t.text);
    if (cls) parts.push(`<span class="${cls}">${safe}</span>`);
    else parts.push(safe);
  }
  // Trailing newline keeps the last visual line aligned with the
  // textarea (browsers collapse a trailing '\n' in <pre> otherwise).
  if (!source.endsWith('\n')) parts.push('\n');
  return parts.join('');
}
