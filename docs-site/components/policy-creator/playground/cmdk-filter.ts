// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Pure (DOM-free, React-free) helpers for the Playground command
// palette. Extracted so the matcher can be exercised by node tests
// without dragging the JSX/'use client' surface in.

export interface IndexEntry {
  /** Section id (matches sections/<file>.tsx + accordion id). */
  sectionId: string;
  /** Display label inside the search results. */
  label: string;
  /** Section group, shown as a tag. */
  group: string;
  /** Optional aliases the operator might type ("hec", "url", etc). */
  keywords?: string[];
}

/**
 * Token AND-match scoring. Every whitespace-separated token in `q`
 * must appear somewhere in the entry's haystack (label + group +
 * keywords). Earlier matches and label-hits score higher than later
 * matches and keyword-hits, so "splunk token" surfaces "Splunk HEC
 * sink" above "Webhook signing secret".
 *
 * Empty / whitespace-only queries return the index unmodified — the
 * UI shows the full alphabetical list as a discovery aid.
 */
export function filterIndex<E extends IndexEntry>(idx: E[], q: string): E[] {
  const trimmed = q.trim().toLowerCase();
  if (!trimmed) return idx;
  const tokens = trimmed.split(/\s+/);
  const scored: Array<{ entry: E; score: number }> = [];
  for (const entry of idx) {
    const labelLc = entry.label.toLowerCase();
    const hay = [
      labelLc,
      entry.group.toLowerCase(),
      ...(entry.keywords ?? []).map((k) => k.toLowerCase()),
    ].join(' | ');
    let ok = true;
    let score = 0;
    for (const t of tokens) {
      const at = hay.indexOf(t);
      if (at < 0) {
        ok = false;
        break;
      }
      score += labelLc.includes(t) ? 100 - at : 50 - at;
    }
    if (ok) scored.push({ entry, score });
  }
  scored.sort((a, b) => b.score - a.score);
  return scored.map((s) => s.entry);
}
