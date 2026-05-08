'use client';

import { useEffect, useState } from 'react';

// Lightweight terminal mockup mirroring the operator's first-run
// experience: type the install + connector setup commands, then
// reveal the configuration summary as if the gateway had just
// echoed it. Pure React (no external typewriter library) so the
// landing page stays under one network request for JS payload.
//
// The animation is gated by `prefers-reduced-motion`; users who
// requested reduced motion see the final frame immediately so we
// don't flicker text into place.
const SCRIPT: { kind: 'cmd' | 'out' | 'ok' | 'dim'; text: string }[] = [
  { kind: 'cmd', text: 'curl -LsSf https://raw.githubusercontent.com/cisco-ai-defense/defenseclaw/main/scripts/install.sh | bash' },
  { kind: 'ok', text: '✓ Installed defenseclaw + defenseclaw-gateway' },
  { kind: 'cmd', text: 'defenseclaw setup claude-code' },
  { kind: 'dim', text: '  DefenseClaw — Claude Code observability setup' },
  { kind: 'dim', text: '  ─────────────────────────────────────────────' },
  { kind: 'ok', text: '  ✓ Config saved to ~/.defenseclaw/config.yaml' },
  { kind: 'ok', text: '  ✓ Active connector set to claudecode (claw.mode=claudecode)' },
  { kind: 'ok', text: '  ✓ Gateway restarted — tool calls + prompts now inspected' },
  { kind: 'cmd', text: 'defenseclaw setup guardrail --mode action --human-approval' },
  { kind: 'ok', text: '  ✓ Action mode engaged — destructive ops will pause for review' },
];

// Number of lines visible on first paint. We seed the install command +
// its success line so even a headless screenshot of the very first
// frame captures the "what is this thing doing?" beat. Below this the
// animation takes over and reveals the rest at human-readable cadence.
const INITIAL_STEP = 2;

export function TerminalDemo() {
  // Seed with the install command + ✓ line so the landing and
  // guardrail pages never paint a blank terminal during initial load
  // (headless capture, slow JS hydration, throttled CPUs all looked
  // empty before this fix).
  const [step, setStep] = useState(INITIAL_STEP);
  const [reduced, setReduced] = useState(false);

  useEffect(() => {
    const m = window.matchMedia('(prefers-reduced-motion: reduce)');
    setReduced(m.matches);
    const onChange = () => setReduced(m.matches);
    m.addEventListener('change', onChange);
    return () => m.removeEventListener('change', onChange);
  }, []);

  useEffect(() => {
    if (reduced) {
      setStep(SCRIPT.length);
      return;
    }
    if (step >= SCRIPT.length) return;
    // Pause briefly after the seeded install + ✓ block so the next
    // command (`defenseclaw setup …`) reads as a distinct beat;
    // subsequent lines tick at 650ms for a steady "log streaming" feel.
    const t = window.setTimeout(() => setStep((s) => s + 1), step === INITIAL_STEP ? 700 : 650);
    return () => window.clearTimeout(t);
  }, [step, reduced]);

  return (
    // `w-full min-w-0` keeps the terminal inside its grid cell on narrow
    // phones — long lines (e.g. the install curl) scroll inside the
    // inner <pre overflow-x-auto> instead of pushing the hero grid wider
    // than the viewport.
    <div
      className="terminal-window w-full min-w-0 overflow-hidden rounded-2xl backdrop-blur"
      role="img"
      aria-label="Terminal demo: installing DefenseClaw and configuring the Claude Code connector with action mode and human-in-the-loop approvals."
    >
      <div className="flex items-center gap-2 border-b border-fd-border/60 bg-fd-card/60 px-4 py-2 text-xs text-fd-muted-foreground">
        <span aria-hidden className="size-3 rounded-full bg-red-500/80" />
        <span aria-hidden className="size-3 rounded-full bg-yellow-500/80" />
        <span aria-hidden className="size-3 rounded-full bg-green-500/80" />
        <span className="ml-3 font-mono">~/projects/agent-gateway</span>
      </div>
      <pre className="m-0 overflow-x-auto p-5 font-mono text-[13px] leading-6 text-fd-foreground">
        {SCRIPT.slice(0, step).map((line, i) => (
          <Line key={i} kind={line.kind} text={line.text} />
        ))}
        {step < SCRIPT.length && (
          <span aria-hidden className="terminal-cursor inline-block w-2 bg-[var(--brand-cisco)]">
            &nbsp;
          </span>
        )}
      </pre>
    </div>
  );
}

function Line({ kind, text }: { kind: 'cmd' | 'out' | 'ok' | 'dim'; text: string }) {
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
