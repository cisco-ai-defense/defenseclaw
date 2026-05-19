// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Lightweight, client-side Rego linter. We do NOT ship the OPA
// compiler in the browser — at v1, the wizard's job is to catch the
// common shape mistakes that prevent `opa check` from ever loading
// the file. The install script the operator runs locally will
// surface the real compile errors when they happen.
//
// Heuristics intentionally err on the side of false-negative (don't
// over-warn) so operators can still author exotic Rego when they
// know what they're doing.

export interface RegoFinding {
  line: number;
  message: string;
  level: 'error' | 'warning' | 'info';
}

export function lintRego(source: string): RegoFinding[] {
  const out: RegoFinding[] = [];
  const lines = source.split('\n');

  let sawPackage = false;
  let openBraces = 0;
  let openBrackets = 0;
  let openParens = 0;

  for (let i = 0; i < lines.length; i += 1) {
    const raw = lines[i];
    const line = raw.replace(/#.*$/, '');
    const trimmed = line.trim();
    const ln = i + 1;

    if (/^package\s+/.test(trimmed)) {
      sawPackage = true;
      if (!/^package\s+defenseclaw\.custom\./.test(trimmed)) {
        out.push({
          line: ln,
          level: 'warning',
          message:
            'Custom Rego should declare its package under "defenseclaw.custom.<name>" so it can be data-namespaced cleanly.',
        });
      }
    }

    if (/\bimport\s+rego\.v1\b/.test(trimmed)) {
      // good
    } else if (/^import\s+/.test(trimmed) && !/\brego\./.test(trimmed)) {
      // imports of other packages are fine, just informational
    }

    if (/^[a-zA-Z_][\w]*\s*=[^=]/.test(trimmed) && !/:=/.test(trimmed)) {
      out.push({
        line: ln,
        level: 'error',
        message:
          'Use ":=" for local assignments (e.g. `x := 1`). The single "=" form is for unification and is rarely what you want.',
      });
    }

    if (/\beval\b|\bsh\b/.test(trimmed) && !/^\s*#/.test(trimmed)) {
      out.push({
        line: ln,
        level: 'info',
        message:
          'Custom Rego cannot reach external systems. Check that "eval"/"sh" references are comments or string literals only.',
      });
    }

    for (const c of line) {
      if (c === '{') openBraces += 1;
      else if (c === '}') openBraces -= 1;
      else if (c === '[') openBrackets += 1;
      else if (c === ']') openBrackets -= 1;
      else if (c === '(') openParens += 1;
      else if (c === ')') openParens -= 1;
    }
  }

  if (!sawPackage) {
    out.push({
      line: 1,
      level: 'error',
      message: 'Snippet must declare a "package defenseclaw.custom.<name>" header.',
    });
  }
  if (openBraces !== 0) {
    out.push({
      line: lines.length,
      level: 'error',
      message: `Unbalanced curly braces: net ${openBraces > 0 ? `+${openBraces}` : openBraces}.`,
    });
  }
  if (openBrackets !== 0) {
    out.push({
      line: lines.length,
      level: 'error',
      message: `Unbalanced square brackets: net ${openBrackets > 0 ? `+${openBrackets}` : openBrackets}.`,
    });
  }
  if (openParens !== 0) {
    out.push({
      line: lines.length,
      level: 'error',
      message: `Unbalanced parentheses: net ${openParens > 0 ? `+${openParens}` : openParens}.`,
    });
  }

  return out;
}
