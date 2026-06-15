// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Searchable picker over the build-time recipe catalog. Used by the
// Rules / Suppressions / Sensitive Tools / Judges sections to drop a
// pre-cooked entry into the wizard. Filters by kind so "secrets"
// rules don't show up under the "tool suppression" picker.

'use client';

import { useMemo, useState } from 'react';
import recipesData from '@/data/policy-recipes.json';
import type { Recipe, RecipeKind, RecipesFile } from '../types';

const ALL: Recipe[] = (recipesData as unknown as RecipesFile).recipes;

export function RecipePicker({
  kinds,
  onPick,
  placeholder = 'Search recipes…',
  maxHeight = 240,
}: {
  kinds: RecipeKind[];
  onPick: (recipe: Recipe) => void;
  placeholder?: string;
  maxHeight?: number;
}) {
  const [query, setQuery] = useState('');
  const filtered = useMemo(() => {
    const set = new Set(kinds);
    const q = query.trim().toLowerCase();
    return ALL.filter((r) => set.has(r.kind)).filter((r) => {
      if (!q) return true;
      return (
        r.title.toLowerCase().includes(q) ||
        r.id.toLowerCase().includes(q) ||
        r.tags.some((t) => t.toLowerCase().includes(q)) ||
        JSON.stringify(r.body).toLowerCase().includes(q)
      );
    });
  }, [query, kinds]);

  return (
    <div className="space-y-1">
      <input
        type="text"
        value={query}
        onChange={(e) => setQuery(e.target.value)}
        placeholder={placeholder}
        className="w-full rounded-md border border-fd-border bg-fd-background px-2 py-1.5 text-xs text-fd-foreground placeholder:text-fd-muted-foreground/60 focus:border-[var(--brand-cisco)] focus:outline-none focus:ring-1 focus:ring-[var(--brand-cisco)]"
      />
      <div
        className="space-y-1 overflow-y-auto rounded-md border border-fd-border bg-fd-background"
        style={{ maxHeight }}
      >
        {filtered.length === 0 ? (
          <p className="px-2 py-3 text-center text-[11px] text-fd-muted-foreground">
            No recipes match.
          </p>
        ) : (
          filtered.map((r) => (
            <button
              key={r.id}
              type="button"
              onClick={() => onPick(r)}
              className="flex w-full flex-col items-start gap-0.5 border-b border-fd-border px-2.5 py-1.5 text-left transition-colors last:border-b-0 hover:bg-fd-muted/40"
            >
              <div className="flex w-full items-center gap-2">
                <span className="truncate text-xs font-medium text-fd-foreground">{r.title}</span>
                <span className="ml-auto rounded-full bg-fd-muted px-1.5 py-0.5 text-[9px] uppercase tracking-wide text-fd-muted-foreground">
                  {r.kind}
                </span>
              </div>
              <span className="line-clamp-2 text-[10px] leading-snug text-fd-muted-foreground">
                {r.why}
              </span>
              {r.tags.length > 0 && (
                <span className="text-[9px] text-fd-muted-foreground/70">
                  {r.tags.slice(0, 5).join(' · ')}
                </span>
              )}
            </button>
          ))
        )}
      </div>
    </div>
  );
}
