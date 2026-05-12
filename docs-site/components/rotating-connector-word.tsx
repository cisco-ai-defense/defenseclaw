'use client';

import { useEffect, useState } from 'react';
import { useHeroLockup } from './hero-lockup';

// Hero word that swaps through every connector label so the headline
// reads as a promise to the entire connector matrix, not just one.
//
// Two modes:
//   1. Inside <HeroLockup> — reads the rotation index from context so
//      it stays in lockstep with the terminal demo (page hero usage).
//   2. Standalone — runs its own 2.2s interval rotation across a
//      caller-supplied list. Lets the component drop into MDX or
//      anywhere else outside the hero without dragging the lockup.

const STANDALONE_INTERVAL_MS = 2200;

interface RotatingConnectorWordProps {
  // Optional override for the standalone rotation list. Ignored when
  // mounted inside a <HeroLockup> (context wins).
  words?: string[];
}

export function RotatingConnectorWord({ words }: RotatingConnectorWordProps) {
  const lockup = useHeroLockup();
  const [standaloneIdx, setStandaloneIdx] = useState(0);

  // Standalone rotation. Skipped (and the interval is never created)
  // when we're inside a HeroLockup context, where the parent owns
  // the rotation cadence.
  useEffect(() => {
    if (lockup) return;
    if (!words || words.length === 0) return;
    const id = window.setInterval(() => {
      setStandaloneIdx((prev) => (prev + 1) % words.length);
    }, STANDALONE_INTERVAL_MS);
    return () => window.clearInterval(id);
  }, [lockup, words]);

  const list = lockup?.words ?? words ?? [];
  if (list.length === 0) return null;
  const index = lockup ? lockup.index : standaloneIdx;
  const current = list[index % list.length];

  // `whitespace-nowrap` keeps multi-word connector names ("Claude Code",
  // "GitHub Copilot CLI") from breaking mid-rotation. The h1 itself
  // owns `text-balance` so the surrounding line rebalances naturally
  // when the word swaps. The keyed inner span retriggers the
  // single-shot fade-up animation defined in global.css on every tick.
  return (
    <span
      className="inline-block whitespace-nowrap text-[var(--brand-cisco-strong)]"
      aria-live="polite"
    >
      <span key={current} className="connector-word-in inline-block">
        {current}
      </span>
    </span>
  );
}
