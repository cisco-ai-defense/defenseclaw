'use client';

import { useEffect, useRef, useState } from 'react';

import {
  TERMINAL_CONNECTORS,
  type ConnectorBlock,
} from '@/lib/hero-connectors';
import { useHeroLockup } from './hero-lockup';

// Re-export so callers that already imported `TERMINAL_CONNECTORS`
// from this module keep working. The canonical home is
// `@/lib/hero-connectors` (a data module, not a client component) so
// hero-lockup can read it without dragging in this component.
export { TERMINAL_CONNECTORS } from '@/lib/hero-connectors';

// Terminal mockup that types the install command + a per-connector
// `defenseclaw setup ...` block, then settles. The rotation index
// comes from <HeroLockup>'s context — when the parent advances we
// re-type the per-connector block from scratch (the install header
// stays pinned). When mounted outside the lockup the component runs
// its own internal rotation interval so it stays usable as a generic
// MDX widget.

type LineKind = 'cmd' | 'out' | 'ok' | 'dim';
interface ScriptLine {
  kind: LineKind;
  text: string;
}

const INSTALL_VERSION = '0.8.6';

// Static header — typed once on initial mount and never replayed.
// `defenseclaw-gateway` is the canonical companion install line and
// every connector setup runs after it.
const HEADER: ScriptLine[] = [
  {
    kind: 'cmd',
    text: `curl -LsSf https://raw.githubusercontent.com/cisco-ai-defense/defenseclaw/${INSTALL_VERSION}/scripts/install.sh | VERSION=${INSTALL_VERSION} bash`,
  },
  { kind: 'ok', text: '✓ Installed defenseclaw + defenseclaw-gateway' },
];

// Per-connector replay block — five lines so the typewriter completes
// in ~1.4s at 280ms/line and leaves the user ~0.9s to read the
// settled state before the next rotation (cadence enforced by
// <HeroLockup>'s SETTLE_MS).
function blockFor(c: ConnectorBlock): ScriptLine[] {
  return [
    { kind: 'cmd', text: c.command },
    { kind: 'dim', text: `  DefenseClaw — ${c.label} setup` },
    { kind: 'ok',  text: '  ✓ Config saved to ~/.defenseclaw/config.yaml' },
    { kind: 'ok',  text: `  ✓ Active connector set to ${c.modeId} (claw.mode=${c.modeId})` },
    { kind: 'ok',  text: '  ✓ Gateway restarted — tool calls + prompts now inspected' },
  ];
}

// Header types at the same 280ms/line cadence as the per-connector
// block; the second line waits 700ms after the first so the curl
// command reads as a distinct beat before the success ✓ lands.
const LINE_MS = 280;
const HEADER_BEAT_MS = 700;
// Standalone-mode rotation cadence (used only when this component
// renders outside <HeroLockup>). Mirrors the lockup's SETTLE_MS so
// MDX usages feel the same — typewriter (~1.4s) + ~3.8s read time
// gives each connector ~5.2s on screen.
const STANDALONE_HOLD_MS = 3800;

export function TerminalDemo() {
  const lockup = useHeroLockup();
  const [standaloneIdx, setStandaloneIdx] = useState(0);
  // Local nudge ref used to advance standalone mode when the
  // typewriter finishes. Lives outside the rotation timer so we can
  // hold for STANDALONE_HOLD_MS after each completion.
  const standaloneTimer = useRef<number | null>(null);

  useEffect(() => {
    return () => {
      if (standaloneTimer.current !== null) {
        window.clearTimeout(standaloneTimer.current);
      }
    };
  }, []);

  const connectorIdx = lockup ? lockup.index : standaloneIdx;
  const connector =
    TERMINAL_CONNECTORS[connectorIdx % TERMINAL_CONNECTORS.length];
  const block = blockFor(connector);

  const [reduced, setReduced] = useState(false);
  // Header step: 0 = nothing, 1 = curl typed, 2 = ✓ shown. Once it
  // reaches HEADER.length it stays there for the rest of the page
  // lifetime — the install header is pinned, never replayed.
  const [headerStep, setHeaderStep] = useState(0);
  // Per-connector typewriter step. Reset to 0 every time
  // `connector.id` changes (the keyed React effect below). When it
  // reaches block.length, `onDone()` fires and the parent advances.
  const [blockStep, setBlockStep] = useState(0);

  // Reduced-motion: jump straight to settled state and trigger the
  // rotation cadence so the rotating word still ticks (otherwise it
  // would freeze on connector 0 forever).
  useEffect(() => {
    const m = window.matchMedia('(prefers-reduced-motion: reduce)');
    setReduced(m.matches);
    const onChange = () => setReduced(m.matches);
    m.addEventListener('change', onChange);
    return () => m.removeEventListener('change', onChange);
  }, []);

  // Header typewriter. Runs once on mount. Skip if reduced-motion.
  useEffect(() => {
    if (reduced) {
      setHeaderStep(HEADER.length);
      return;
    }
    if (headerStep >= HEADER.length) return;
    const delay = headerStep === 1 ? HEADER_BEAT_MS : LINE_MS;
    const t = window.setTimeout(() => setHeaderStep((s) => s + 1), delay);
    return () => window.clearTimeout(t);
  }, [headerStep, reduced]);

  // Per-connector typewriter. Resets when connector id changes so a
  // rotation always replays from the top of the block.
  useEffect(() => {
    setBlockStep(0);
  }, [connector.id]);

  useEffect(() => {
    // Wait until the install header is fully on screen before the
    // first connector block starts — keeps the very first paint from
    // looking double-busy.
    if (headerStep < HEADER.length) return;

    if (reduced) {
      setBlockStep(block.length);
    }

    if (blockStep >= block.length) {
      // Block finished. Tell the parent (or schedule our own
      // standalone rotation) so we settle for a beat before the next
      // typewriter run.
      if (lockup) {
        lockup.onDone();
      } else {
        if (standaloneTimer.current !== null) {
          window.clearTimeout(standaloneTimer.current);
        }
        standaloneTimer.current = window.setTimeout(() => {
          setStandaloneIdx((prev) => (prev + 1) % TERMINAL_CONNECTORS.length);
        }, STANDALONE_HOLD_MS);
      }
      return;
    }

    if (reduced) return;

    const t = window.setTimeout(() => setBlockStep((s) => s + 1), LINE_MS);
    return () => window.clearTimeout(t);
  }, [headerStep, blockStep, block.length, reduced, lockup]);

  const headerVisible = HEADER.slice(0, headerStep);
  const blockVisible = block.slice(0, blockStep);
  const showCursor =
    !reduced && (headerStep < HEADER.length || blockStep < block.length);

  return (
    // `w-full min-w-0` keeps the terminal inside its grid cell on narrow
    // phones. The inner <pre> wraps long lines via
    // `whitespace-pre-wrap wrap-anywhere` — preserves the indented
    // "  ✓ …" success lines while letting the long install curl URL
    // (no spaces) break at any character so it never side-scrolls.
    <div
      className="terminal-window w-full min-w-0 overflow-hidden rounded-2xl backdrop-blur"
      role="img"
      aria-label={`Terminal demo: installing DefenseClaw and configuring the ${connector.label} connector.`}
    >
      <div className="flex items-center gap-2 border-b border-fd-border/60 bg-fd-card/60 px-4 py-2 text-xs text-fd-muted-foreground">
        <span aria-hidden className="size-3 rounded-full bg-red-500/80" />
        <span aria-hidden className="size-3 rounded-full bg-yellow-500/80" />
        <span aria-hidden className="size-3 rounded-full bg-green-500/80" />
        <span className="ml-3 font-mono">~/projects/agent-gateway</span>
      </div>
      <pre className="m-0 whitespace-pre-wrap wrap-anywhere p-5 font-mono text-[13px] leading-6 text-fd-foreground">
        {headerVisible.map((line, i) => (
          <Line key={`h-${i}`} kind={line.kind} text={line.text} />
        ))}
        {/* Keying the block container on connector id forces React to
            unmount the previous connector's lines wholesale — there's
            no half-typed-block-from-the-previous-rotation flicker. */}
        <div key={`block-${connector.id}`}>
          {blockVisible.map((line, i) => (
            <Line key={`b-${i}`} kind={line.kind} text={line.text} />
          ))}
        </div>
        {showCursor && (
          <span aria-hidden className="terminal-cursor inline-block w-2 bg-[var(--brand-cisco)]">
            &nbsp;
          </span>
        )}
      </pre>
    </div>
  );
}

function Line({ kind, text }: { kind: LineKind; text: string }) {
  if (kind === 'cmd') {
    return (
      <div>
        <span className="text-[var(--brand-cisco)]">$ </span>
        <span>{text}</span>
      </div>
    );
  }
  if (kind === 'ok') {
    return <div className="text-emerald-500">{text}</div>;
  }
  if (kind === 'dim') {
    return <div className="text-fd-muted-foreground">{text}</div>;
  }
  return <div>{text}</div>;
}
