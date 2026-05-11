// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Lightweight syntax-highlighted code editor. No CodeMirror, no
// Monaco — just a transparent <textarea> stacked over a <pre> that
// renders the highlighted source. Both share identical typography
// and padding so the cursor lines up perfectly with the highlighted
// text underneath.
//
// Why this approach?
//   - Bundle: zero new deps. CodeMirror 6 is ~150KB, Monaco is
//     ~500KB + a worker. For the niche surfaces that need a real
//     editor (custom-rego, BYO test input), that's prohibitive.
//   - Behavior: all native textarea affordances (selection, IME,
//     undo/redo, accessibility) work for free; we only intercept Tab
//     to insert two spaces.
//   - Maintenance: each tokenizer is ~100 LOC and the overlay is a
//     single <pre>, so future-me can debug it in 5 minutes.
//
// Tradeoffs we accept:
//   - No real autocomplete or hover docs.
//   - Highlighting is presentation-only; the authoritative parse
//     happens elsewhere (`opa check` for Rego, `JSON.parse` for the
//     live-test input).
//   - Line numbers re-render on every keystroke; for snippets up to
//     a few hundred lines this is fine.
//
// The export name stays `RegoEditor` for backwards compat with
// existing call sites; new callers should use the language-agnostic
// `CodeEditor` alias and pass `language` + `highlight` explicitly.

'use client';

import { useEffect, useMemo, useRef, type ReactNode } from 'react';
import { highlightRegoToHtml } from '../lib/rego-highlight';

export interface CodeEditorProps {
  label: string;
  hint?: ReactNode;
  value: string;
  onChange: (next: string) => void;
  /** Visible rows when empty. Editor will not shrink below this. */
  minRows?: number;
  /** Short language label rendered in the top-right of the editor
   *  (e.g. "rego", "json"). Defaults to "rego" for backwards compat. */
  language?: string;
  /** Tokenize-and-render function. Receives the raw source string,
   *  returns syntax-highlighted HTML. Defaults to the Rego highlighter. */
  highlight?: (source: string) => string;
  /** Placeholder shown when value is empty. */
  placeholder?: string;
}

const TAB_REPLACEMENT = '  '; // 2-space indents are conventional in both Rego + JSON.

const DEFAULT_PLACEHOLDER =
  "Write Rego here. The bundled modules cover most use cases — only override when you need a verdict the defaults can't express.";

export function CodeEditor({
  label,
  hint,
  value,
  onChange,
  minRows = 14,
  language = 'rego',
  highlight = highlightRegoToHtml,
  placeholder = DEFAULT_PLACEHOLDER,
}: CodeEditorProps) {
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const overlayRef = useRef<HTMLPreElement>(null);
  const gutterRef = useRef<HTMLPreElement>(null);

  // Pre-rendered highlighted HTML; recompute only when the source
  // changes.
  const highlighted = useMemo(() => highlight(value), [highlight, value]);

  // Line-number gutter content. Always at least minRows so an empty
  // editor still shows the rule of available rows.
  const lineCount = Math.max(value.split('\n').length, minRows);
  const gutterText = useMemo(() => {
    const out: string[] = [];
    for (let i = 1; i <= lineCount; i += 1) out.push(String(i));
    return out.join('\n');
  }, [lineCount]);

  // Sync overlay scroll position to textarea scroll. We sync both
  // axes so long lines line up horizontally too.
  useEffect(() => {
    const ta = textareaRef.current;
    const overlay = overlayRef.current;
    const gutter = gutterRef.current;
    if (!ta || !overlay) return;
    const onScroll = () => {
      overlay.scrollTop = ta.scrollTop;
      overlay.scrollLeft = ta.scrollLeft;
      if (gutter) gutter.scrollTop = ta.scrollTop;
    };
    ta.addEventListener('scroll', onScroll);
    return () => ta.removeEventListener('scroll', onScroll);
  }, []);

  // Tab key inserts spaces instead of moving focus. Shift-Tab dedents
  // the current line by up to 2 leading spaces.
  function onKeyDown(e: React.KeyboardEvent<HTMLTextAreaElement>) {
    if (e.key !== 'Tab') return;
    e.preventDefault();
    const ta = e.currentTarget;
    const start = ta.selectionStart;
    const end = ta.selectionEnd;
    if (e.shiftKey) {
      // Dedent the current line(s).
      const before = value.slice(0, start);
      const lineStart = before.lastIndexOf('\n') + 1;
      const head = value.slice(lineStart, start);
      const dropped = head.replace(/^ {1,2}/, '');
      const removed = head.length - dropped.length;
      if (removed === 0) return;
      const next =
        value.slice(0, lineStart) + dropped + value.slice(start);
      onChange(next);
      // Restore caret accounting for removed spaces.
      requestAnimationFrame(() => {
        ta.selectionStart = ta.selectionEnd = start - removed;
      });
      return;
    }
    const next = value.slice(0, start) + TAB_REPLACEMENT + value.slice(end);
    onChange(next);
    requestAnimationFrame(() => {
      ta.selectionStart = ta.selectionEnd = start + TAB_REPLACEMENT.length;
    });
  }

  return (
    <div className="flex flex-col gap-1">
      <div className="flex items-center justify-between">
        <span className="text-xs font-medium text-fd-muted-foreground">{label}</span>
        <span className="text-[10px] uppercase tracking-wide text-fd-muted-foreground">
          {language}
        </span>
      </div>
      <div className="relative overflow-hidden rounded-md border border-fd-border bg-fd-background focus-within:border-[var(--brand-cisco)] focus-within:ring-1 focus-within:ring-[var(--brand-cisco)]">
        <div className="flex">
          <pre
            ref={gutterRef}
            aria-hidden="true"
            className="select-none border-r border-fd-border bg-fd-card/40 px-2 py-2 text-right font-mono text-[11px] leading-5 text-fd-muted-foreground"
            // Fixed-width gutter sized to fit up to 4 digits.
            style={{ width: '2.4rem', overflow: 'hidden', maxHeight: 'inherit' }}
          >
            {gutterText}
          </pre>
          <div className="relative flex-1">
            {/* Highlighted overlay positioned absolutely behind the
             *  transparent textarea. Uses the exact same font, line
             *  height, padding, and tab size so the cursor lines up
             *  with characters underneath. pointer-events:none lets
             *  the textarea capture all mouse events. */}
            <pre
              ref={overlayRef}
              aria-hidden="true"
              className="pointer-events-none absolute inset-0 m-0 overflow-auto whitespace-pre px-2 py-2 font-mono text-[12px] leading-5"
              dangerouslySetInnerHTML={{ __html: highlighted }}
            />
            <textarea
              ref={textareaRef}
              value={value}
              onChange={(e) => onChange(e.target.value)}
              onKeyDown={onKeyDown}
              spellCheck={false}
              autoComplete="off"
              autoCorrect="off"
              autoCapitalize="off"
              rows={Math.min(Math.max(value.split('\n').length, minRows), 32)}
              className="relative block w-full resize-y bg-transparent px-2 py-2 font-mono text-[12px] leading-5 text-transparent caret-fd-foreground placeholder:text-fd-muted-foreground focus:outline-none"
              style={{
                // Match the overlay exactly. tab-size=2 matches our
                // TAB_REPLACEMENT so anyone pasting in tab-indented
                // code still aligns visually.
                tabSize: 2,
                WebkitTextFillColor: 'transparent',
              }}
              placeholder={placeholder}
            />
          </div>
        </div>
      </div>
      {hint && <span className="text-[11px] text-fd-muted-foreground">{hint}</span>}
    </div>
  );
}

/** Backwards-compat alias. Existing call sites import { RegoEditor };
 *  they get a CodeEditor with the Rego defaults baked in. New callers
 *  should import { CodeEditor } and pass language + highlight. */
export type RegoEditorProps = Omit<CodeEditorProps, 'language' | 'highlight'>;
export function RegoEditor(props: RegoEditorProps) {
  return <CodeEditor {...props} />;
}
