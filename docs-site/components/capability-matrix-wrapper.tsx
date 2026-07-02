'use client';

import { useEffect, type ReactNode } from 'react';
import { useScrollable } from '@/hooks/use-scrollable';

// One-shot viewport observer for the capability matrix table. Flips
// `data-animate="entered"` on the wrapper once the table scrolls into
// view, which gates the row-stagger keyframe defined in global.css.
// SSR markup stays unchanged — the table renders to its final state
// until JS hydrates and the IntersectionObserver fires.

interface CapabilityMatrixWrapperProps {
  children: ReactNode;
  className?: string;
  ariaLabel?: string;
}

export function CapabilityMatrixWrapper({
  children,
  className,
  ariaLabel = 'Connector capability matrix',
}: CapabilityMatrixWrapperProps) {
  const { ref, scrollable } = useScrollable<HTMLDivElement>();

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    if (el.dataset.animate === 'entered') return;
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
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
      { rootMargin: '0px 0px -10% 0px', threshold: 0.1 },
    );
    io.observe(el);
    return () => io.disconnect();
  }, []);

  return (
    <div
      ref={ref}
      className={className}
      role={scrollable ? 'region' : undefined}
      aria-label={scrollable ? ariaLabel : undefined}
      tabIndex={scrollable ? 0 : undefined}
    >
      {children}
    </div>
  );
}
