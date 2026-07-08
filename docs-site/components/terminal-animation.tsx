'use client';

import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from 'react';

// TerminalAnimation — a faithful, scriptable terminal "movie".
//
// Every frame is one of:
//   - cmd      typed at $ prompt (typewriter)
//   - prompt   instant prompt label, then typewriter the user's reply
//   - out      instant plain output line
//   - ok       instant green output line ("✓ ...")
//   - warn     instant amber line
//   - dim      instant muted line (banners, helper text)
//   - spacer   blank line
//
// We deliberately keep this dependency-free (no external typewriter
// or animation lib) so the docs payload stays small. The play loop
// runs inside a single useEffect with a cancellation token; refs
// hold the live "paused" flag so pause-on-hover and the Pause button
// take effect without re-arming the whole effect.
//
// Reduced motion: users who set prefers-reduced-motion see the final
// frame immediately and never enter the play loop.

export type TerminalFrameType =
  | 'cmd'
  | 'prompt'
  | 'out'
  | 'ok'
  | 'warn'
  | 'dim'
  | 'spacer';

export interface TerminalFrame {
  type: TerminalFrameType;
  text?: string;
  /** For 'prompt' frames: the user's typed reply. Empty string = "press Enter for default". */
  reply?: string;
  /** Per-character delay in ms (typewriter speed). Default ~32ms. */
  charMs?: number;
  /** Pause after this frame in ms. Default ~320ms. */
  pauseMs?: number;
}

export interface TerminalAnimationProps {
  frames: TerminalFrame[];
  caption?: string;
  cwd?: string;
  shell?: string;
  loop?: boolean;
  /** Speed multiplier. 1 = natural, 1.5 = brisk. */
  speed?: number;
  /** Max body height in px. Default 460. */
  height?: number;
  /** Aria description of the demo. */
  ariaLabel?: string;
}

interface RenderedLine {
  type: TerminalFrameType;
  text: string;
  reply: string;
}

const sleep = (ms: number) =>
  new Promise<void>((r) => setTimeout(r, Math.max(0, ms)));

export function TerminalAnimation({
  frames,
  caption,
  cwd = '~/projects/agent-gateway',
  shell = '$',
  loop = true,
  speed = 1,
  height = 460,
  ariaLabel,
}: TerminalAnimationProps) {
  const [rendered, setRendered] = useState<RenderedLine[]>([]);
  const [paused, setPaused] = useState(false);
  const [reduced, setReduced] = useState(false);
  const [done, setDone] = useState(false);
  const [restartTick, setRestartTick] = useState(0);

  const containerRef = useRef<HTMLDivElement | null>(null);
  const preRef = useRef<HTMLPreElement | null>(null);

  // Live paused flag for the async play loop (closure would be stale).
  const pausedRef = useRef(false);
  useEffect(() => {
    pausedRef.current = paused;
  }, [paused]);

  // Reduced-motion preference.
  useEffect(() => {
    if (typeof window === 'undefined') return;
    const m = window.matchMedia('(prefers-reduced-motion: reduce)');
    setReduced(m.matches);
    const handler = (event: MediaQueryListEvent) => setReduced(event.matches);
    m.addEventListener('change', handler);
    return () => m.removeEventListener('change', handler);
  }, []);

  // Pause on hover so readers can study a frame.
  useEffect(() => {
    const node = containerRef.current;
    if (!node) return;
    const onEnter = () => setPaused(true);
    const onLeave = () => setPaused(false);
    node.addEventListener('mouseenter', onEnter);
    node.addEventListener('mouseleave', onLeave);
    return () => {
      node.removeEventListener('mouseenter', onEnter);
      node.removeEventListener('mouseleave', onLeave);
    };
  }, []);

  // Auto-scroll to bottom as new lines render.
  useEffect(() => {
    if (preRef.current) {
      preRef.current.scrollTop = preRef.current.scrollHeight;
    }
  }, [rendered]);

  // Reduced motion: render the final state once, never animate.
  useEffect(() => {
    if (!reduced) return;
    setRendered(
      frames.map((frame) => ({
        type: frame.type,
        text: frame.text ?? '',
        reply: frame.reply ?? '',
      })),
    );
    setDone(true);
  }, [reduced, frames]);

  // Main play loop. Re-runs on Restart (restartTick) and on reduced-motion
  // changes. Frames are read by reference; treat the array as stable per
  // mount (typical when supplied inline from MDX).
  useEffect(() => {
    if (reduced) return;
    let cancelled = false;
    const safeSpeed = Math.max(0.25, speed);

    const waitWhilePaused = async () => {
      while (pausedRef.current && !cancelled) {
        await sleep(120);
      }
    };

    async function play() {
      setRendered([]);
      setDone(false);

      for (const frame of frames) {
        if (cancelled) return;
        await waitWhilePaused();
        if (cancelled) return;

        const charMs = (frame.charMs ?? 32) / safeSpeed;
        const pauseMs = (frame.pauseMs ?? 320) / safeSpeed;
        const text = frame.text ?? '';

        if (frame.type === 'cmd') {
          setRendered((r) => [...r, { type: 'cmd', text: '', reply: '' }]);
          for (let c = 1; c <= text.length; c++) {
            if (cancelled) return;
            await waitWhilePaused();
            setRendered((r) => {
              const copy = r.slice();
              copy[copy.length - 1] = {
                type: 'cmd',
                text: text.slice(0, c),
                reply: '',
              };
              return copy;
            });
            await sleep(charMs);
          }
          await sleep(pauseMs);
        } else if (frame.type === 'prompt') {
          setRendered((r) => [
            ...r,
            { type: 'prompt', text, reply: '' },
          ]);
          await sleep(700 / safeSpeed);
          const reply = frame.reply ?? '';
          for (let c = 1; c <= reply.length; c++) {
            if (cancelled) return;
            await waitWhilePaused();
            setRendered((r) => {
              const copy = r.slice();
              const last = copy[copy.length - 1];
              if (last && last.type === 'prompt') {
                copy[copy.length - 1] = { ...last, reply: reply.slice(0, c) };
              }
              return copy;
            });
            await sleep(charMs * 1.4);
          }
          await sleep(pauseMs);
        } else {
          setRendered((r) => [
            ...r,
            { type: frame.type, text, reply: '' },
          ]);
          await sleep(pauseMs);
        }
      }

      setDone(true);

      if (loop && !cancelled) {
        await sleep(3500 / safeSpeed);
        if (!cancelled) {
          setRestartTick((t) => t + 1);
        }
      }
    }

    play();
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [reduced, restartTick]);

  const onTogglePause = useCallback(() => {
    setPaused((p) => !p);
  }, []);
  const onRestart = useCallback(() => {
    setRestartTick((t) => t + 1);
    setPaused(false);
  }, []);

  const description = useMemo(
    () =>
      ariaLabel ??
      'Animated terminal demo. Pause with the Pause button or by hovering the terminal.',
    [ariaLabel],
  );

  return (
    <figure
      ref={containerRef}
      className="my-6"
      role="group"
      aria-label={description}
    >
      <div className="terminal-window overflow-hidden rounded-2xl border border-fd-border/60 bg-[#0b0d12] backdrop-blur shadow-lg">
        <div className="flex items-center gap-2 border-b border-fd-border/60 bg-[#11141b] px-4 py-2 text-xs text-fd-muted-foreground">
          <span aria-hidden className="size-3 rounded-full bg-red-500/80" />
          <span aria-hidden className="size-3 rounded-full bg-yellow-500/80" />
          <span aria-hidden className="size-3 rounded-full bg-green-500/80" />
          <span className="ml-3 font-mono text-zinc-400">{cwd}</span>
          <div className="ml-auto flex items-center gap-2">
            <span
              aria-live="polite"
              className="hidden font-mono text-[10px] uppercase tracking-wider text-zinc-400 sm:inline"
            >
              {paused ? 'paused' : done ? 'looping' : 'playing'}
            </span>
            <button
              type="button"
              onClick={onTogglePause}
              className="rounded border border-zinc-700 bg-zinc-900 px-2 py-0.5 text-[11px] text-zinc-300 hover:bg-zinc-800"
              aria-label={paused ? 'Resume animation' : 'Pause animation'}
            >
              {paused ? 'Resume' : 'Pause'}
            </button>
            <button
              type="button"
              onClick={onRestart}
              className="rounded border border-zinc-700 bg-zinc-900 px-2 py-0.5 text-[11px] text-zinc-300 hover:bg-zinc-800"
              aria-label="Restart animation"
            >
              Restart
            </button>
          </div>
        </div>
        <pre
          ref={preRef}
          tabIndex={0}
          aria-label="Animated terminal output"
          style={{ maxHeight: height, minHeight: Math.min(220, height) }}
          className="m-0 overflow-x-auto overflow-y-auto p-5 font-mono text-[13px] leading-6 text-zinc-100"
        >
          {rendered.map((line, i) => (
            <Line key={i} line={line} shell={shell} />
          ))}
          {!done ? (
            <span
              aria-hidden
              className="terminal-cursor inline-block w-2 align-text-bottom"
              style={{
                background: 'var(--brand-cisco, #049fd9)',
                height: '1em',
              }}
            >
              &nbsp;
            </span>
          ) : null}
        </pre>
      </div>
      {caption ? (
        <figcaption className="mt-2 text-center text-xs text-fd-muted-foreground">
          {caption}
        </figcaption>
      ) : null}
    </figure>
  );
}

function Line({ line, shell }: { line: RenderedLine; shell: string }) {
  if (line.type === 'cmd') {
    return (
      <div>
        <span style={{ color: 'var(--brand-cisco, #049fd9)' }}>{shell} </span>
        <span className="text-zinc-100">{line.text}</span>
      </div>
    );
  }
  if (line.type === 'prompt') {
    return (
      <div>
        <span className="text-zinc-300">{line.text}</span>
        <span
          className="font-semibold"
          style={{ color: 'var(--brand-orange, #ff7a18)' }}
        >
          {line.reply}
        </span>
      </div>
    );
  }
  if (line.type === 'ok') {
    return <div className="text-emerald-400">{line.text}</div>;
  }
  if (line.type === 'warn') {
    return <div className="text-amber-300">{line.text}</div>;
  }
  if (line.type === 'dim') {
    return <div className="text-zinc-400">{line.text}</div>;
  }
  if (line.type === 'spacer') {
    return <div>&nbsp;</div>;
  }
  return <div className="text-zinc-200">{line.text}</div>;
}
