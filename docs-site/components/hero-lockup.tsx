'use client';

import {
  createContext,
  useContext,
  useEffect,
  useRef,
  useState,
  type ReactNode,
} from 'react';

import { TERMINAL_CONNECTORS } from '@/lib/hero-connectors';

// Owns the rotation index for the hero lockup. The rotating word in
// the headline and the terminal in the right column both subscribe
// to this context, so the headline's "OpenClaw / Claude Code / Codex
// / …" stays in lockstep with the `defenseclaw setup …` line in the
// terminal regardless of how long any one connector's typewriter
// takes.
//
// Cadence is event-driven: when the terminal finishes typing the
// current per-connector block it calls `onDone()`, we hold the
// settled frame for SETTLE_MS, then advance. This beats a fixed
// interval because typewriter durations vary slightly per connector
// (longer commands, longer mode IDs).
//
// Total per-connector beat ≈ typewriter (~1.4s) + SETTLE_MS, sized so
// each connector reads as a deliberate beat with enough dwell time
// for the visitor to scan the `claw.mode=<id>` line and the
// matching headline word before the next swap.
const SETTLE_MS = 3800;

interface HeroLockupContextValue {
  index: number;
  // Called from <TerminalDemo> when the per-connector block finishes
  // typing. Triggers the SETTLE_MS hold + advance.
  onDone: () => void;
  words: string[];
}

const HeroLockupContext = createContext<HeroLockupContextValue | null>(null);

// Consumer hook used by <RotatingConnectorWord> and <TerminalDemo>.
// Returns null when used outside the lockup so those components can
// render in standalone mode (e.g. inside docs MDX) with their own
// internal state — handy for keeping the components reusable.
export function useHeroLockup(): HeroLockupContextValue | null {
  return useContext(HeroLockupContext);
}

// Top-level wrapper. Children are the entire hero section JSX
// (eyebrow, h1 with rotating word, paragraph, CTAs, chip strips,
// terminal column). Page-level layout stays in `page.tsx`.
export function HeroLockup({ children }: { children: ReactNode }) {
  const [index, setIndex] = useState(0);
  const advanceTimer = useRef<number | null>(null);

  useEffect(() => {
    return () => {
      if (advanceTimer.current !== null) {
        window.clearTimeout(advanceTimer.current);
      }
    };
  }, []);

  const onDone = () => {
    if (advanceTimer.current !== null) {
      window.clearTimeout(advanceTimer.current);
    }
    advanceTimer.current = window.setTimeout(() => {
      setIndex((prev) => (prev + 1) % TERMINAL_CONNECTORS.length);
    }, SETTLE_MS);
  };

  const value: HeroLockupContextValue = {
    index,
    onDone,
    words: TERMINAL_CONNECTORS.map((c) => c.label),
  };

  return (
    <HeroLockupContext.Provider value={value}>
      {children}
    </HeroLockupContext.Provider>
  );
}
