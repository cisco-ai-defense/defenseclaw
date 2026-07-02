'use client';

import {
  useCallback,
  useEffect,
  useId,
  useRef,
  useState,
  type ReactNode,
} from 'react';

interface DiagramLightboxProps {
  caption?: string;
  // Natural pixel size of the underlying SVG. Used to layer a CSS
  // rule that scales the SVG down to fit narrow viewports while
  // keeping crisp rendering on wide ones — no JS, no hydration
  // shift.
  naturalWidth: number;
  naturalHeight: number;
  // The diagram's `aria-label` text. Reused as the modal heading so
  // assistive tech announces the same context.
  ariaLabel: string;
  // The SSR-rendered SVG. Rendered once for the inline figure and
  // re-rendered (server-side) inside the modal scroll surface so the
  // expanded view shows the same content at native scale, with no
  // extra HTML emitted unless the modal is open. Modal mounts only
  // when the user clicks the "expand" button.
  children: ReactNode;
  // Marks the figure with `data-oversize="true"` so the build-time
  // width gate (scripts/check-diagram-widths.ts) skips its >1500px
  // check for this diagram. Use only when no smaller layout works.
  oversize?: boolean;
}

// Thin, portal-free client wrapper around the SVG diagrams.
//
//  - Inline render: server-side, scales-to-width via the SVG's own
//    viewBox + max-width constraints (set by callers in <Flow>/
//    <Sequence>). The figure itself does no scaling — it just hosts
//    the SVG and the affordances around it.
//
//  - Expand button: a small icon in the figure's top-right, rendered
//    client-side after hydration. Below SSR (i.e. JS off, prefers
//    static, or before hydration) the button is absent — the figure
//    gracefully degrades to "view at whatever size the column
//    allows" with no broken affordance.
//
//  - Modal: opens a centered overlay with the same SVG at its
//    natural pixel size inside an `overflow: auto` surface, so wide
//    diagrams pan via native scroll and tall diagrams pan via
//    native scroll too. Closes on Esc or click outside the diagram
//    panel. Focus is moved into the close button on open and
//    restored to the trigger on close.
export function DiagramLightbox({
  caption,
  naturalWidth,
  naturalHeight,
  ariaLabel,
  children,
  oversize,
}: DiagramLightboxProps) {
  const [open, setOpen] = useState(false);
  const [hydrated, setHydrated] = useState(false);
  const triggerRef = useRef<HTMLButtonElement | null>(null);
  const closeRef = useRef<HTMLButtonElement | null>(null);
  const surfaceRef = useRef<HTMLDivElement | null>(null);
  const figureRef = useRef<HTMLElement | null>(null);
  const titleId = useId();
  const captionId = useId();

  useEffect(() => {
    setHydrated(true);
  }, []);

  const handleClose = useCallback(() => {
    setOpen(false);
    requestAnimationFrame(() => {
      triggerRef.current?.focus();
    });
  }, []);

  // One-shot viewport intersection trigger. The Flow / Sequence /
  // capability-matrix CSS animations are gated on
  // `data-animate="entered"` on this <figure>, so the SSR-rendered
  // SVG paints to its final state until JS hydrates and the diagram
  // scrolls into view. Once entered, we disconnect — the animation
  // runs exactly once per page visit and never replays on scrollback.
  useEffect(() => {
    const el = figureRef.current;
    if (!el) return;
    if (el.dataset.animate === 'entered') return;
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
      // Reduced-motion: still set the attribute so any conditional
      // styling that depends on it (e.g. final-state colours) is
      // applied; the keyframes themselves are no-ops via the global
      // reduced-motion guard in global.css.
      el.dataset.animate = 'entered';
      return;
    }
    const io = new IntersectionObserver(
      (entries) => {
        for (const e of entries) {
          if (e.isIntersecting) {
            el.dataset.animate = 'entered';
            io.disconnect();
            break;
          }
        }
      },
      { rootMargin: '0px 0px -10% 0px', threshold: 0.15 },
    );
    io.observe(el);
    return () => io.disconnect();
  }, []);

  // Esc-to-close + restore focus to the trigger when the modal closes.
  // We attach the listener at the document level rather than the
  // dialog itself because the modal panel may not be focused at the
  // moment of the keypress (e.g. the user clicked the SVG to scroll).
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.preventDefault();
        handleClose();
      }
    };
    document.addEventListener('keydown', onKey);

    // Move focus into the modal so screen readers and keyboard users
    // pick up the new context. Defer past the first paint so the
    // close button has been mounted.
    const t = setTimeout(() => {
      closeRef.current?.focus();
    }, 0);

    // Lock body scroll while modal is open. Restored unconditionally
    // in the cleanup so a transient open/close never leaks state.
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';

    return () => {
      document.removeEventListener('keydown', onKey);
      clearTimeout(t);
      document.body.style.overflow = previousOverflow;
    };
  }, [handleClose, open]);

  const handleSurfaceClick = useCallback(
    (e: React.MouseEvent<HTMLDivElement>) => {
      // Click-outside semantics: if the click landed on the dimmed
      // backdrop (the surface container itself, not on the panel
      // content), close the modal.
      if (e.target === surfaceRef.current) {
        handleClose();
      }
    },
    [handleClose],
  );

  return (
    <figure
      ref={figureRef}
      className="diagram-figure my-8 not-prose relative group"
      data-oversize={oversize ? 'true' : undefined}
      data-natural-width={naturalWidth}
      data-natural-height={naturalHeight}
    >
      <div className="diagram-canvas overflow-x-auto">
        {children}
      </div>

      {hydrated && (
        <button
          ref={triggerRef}
          type="button"
          onClick={() => setOpen(true)}
          aria-label={`Open at full size: ${ariaLabel}`}
          // Always visible on touch (no hover state) so mobile users
          // can find the expand affordance; reveal-on-hover at sm+
          // keeps the button from competing with the diagram itself
          // at desktop reading widths.
          className="diagram-expand absolute right-3 top-3 inline-flex items-center justify-center p-2 transition focus:outline-2 focus:outline-(--brand-cisco) sm:opacity-0 sm:focus:opacity-100 sm:group-hover:opacity-100"
        >
          <svg
            aria-hidden
            width="14"
            height="14"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          >
            <path d="M15 3h6v6" />
            <path d="M9 21H3v-6" />
            <path d="m21 3-7 7" />
            <path d="m3 21 7-7" />
          </svg>
        </button>
      )}

      {caption && (
        <figcaption
          id={captionId}
          className="diagram-caption"
        >
          {caption}
        </figcaption>
      )}

      {open && (
        <div
          ref={surfaceRef}
          role="dialog"
          aria-modal="true"
          aria-labelledby={titleId}
          aria-describedby={caption ? captionId : undefined}
          onClick={handleSurfaceClick}
          className="fixed inset-0 z-50 flex items-stretch justify-stretch bg-black/75 p-4 sm:p-8"
        >
          <div
            data-animate="entered"
            className="diagram-modal-panel relative flex h-full w-full flex-col border bg-fd-background shadow-2xl"
          >
            <div className="flex items-center justify-between gap-4 border-b border-fd-border px-4 py-3">
              <h2
                id={titleId}
                className="truncate text-sm font-semibold text-fd-foreground"
              >
                {ariaLabel}
              </h2>
              <button
                ref={closeRef}
                type="button"
                onClick={handleClose}
                aria-label="Close diagram"
                className="inline-flex shrink-0 items-center gap-1.5 border border-fd-border bg-fd-card px-2.5 py-1 text-xs font-medium text-fd-muted-foreground transition hover:border-(--brand-cisco) hover:text-fd-foreground"
              >
                <span>Close</span>
                <kbd className="border border-fd-border bg-fd-background px-1 font-mono text-[10px]">
                  Esc
                </kbd>
              </button>
            </div>
            <div
              className="flex-1 overflow-auto p-4 sm:p-6"
              // Ensure inner SVG renders at natural size inside the
              // scroll surface even if it inherited a `width: 100%`
              // style from the inline render. The wrapper sets a
              // floor at the natural diagram size so wide diagrams
              // pan horizontally and tall ones pan vertically.
              style={
                {
                  ['--diagram-w' as string]: `${naturalWidth}px`,
                  ['--diagram-h' as string]: `${naturalHeight}px`,
                } as React.CSSProperties
              }
            >
              <div className="mx-auto [&>svg]:w-(--diagram-w)! [&>svg]:h-(--diagram-h)! [&>svg]:max-w-none!">
                {children}
              </div>
            </div>
            {caption && (
              <p className="border-t border-fd-border px-4 py-3 text-center text-xs text-fd-muted-foreground">
                {caption}
              </p>
            )}
          </div>
        </div>
      )}
    </figure>
  );
}
