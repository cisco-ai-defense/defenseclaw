'use client';

import Link from 'next/link';
import { useEffect, useRef, type ReactNode } from 'react';

// Bottom-CTA "Install DefenseClaw" button. Wraps the underlying <Link>
// with an IntersectionObserver that fires the .cta-pulse keyframe
// exactly once on first viewport entry. Pure CSS pulse — the JS just
// adds the class and removes it on `animationend` so subsequent
// scrolls don't re-trigger.
//
// Style props are forwarded so the parent owns the visual identity
// (size, background, text colour); this component only owns the
// pulse trigger so the animation can be added or pulled without
// touching the styling tokens elsewhere.

interface CtaGlowButtonProps {
  href: string;
  children: ReactNode;
  className?: string;
}

export function CtaGlowButton({ href, children, className }: CtaGlowButtonProps) {
  const linkRef = useRef<HTMLAnchorElement | null>(null);
  const firedRef = useRef(false);

  useEffect(() => {
    const el = linkRef.current;
    if (!el) return;

    const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    if (reduced || firedRef.current) return;

    const io = new IntersectionObserver(
      (entries) => {
        for (const e of entries) {
          if (e.isIntersecting && !firedRef.current) {
            firedRef.current = true;
            el.classList.add('cta-pulse');
            // Auto-remove the class once the animation finishes so
            // class lists stay clean and the animation never replays
            // (e.g. if the user scrolls past and back, which would
            // otherwise re-trigger if the browser ever recalculates).
            const onEnd = () => {
              el.classList.remove('cta-pulse');
              el.removeEventListener('animationend', onEnd);
            };
            el.addEventListener('animationend', onEnd);
            io.disconnect();
          }
        }
      },
      { rootMargin: '0px 0px -10% 0px', threshold: 0.4 },
    );
    io.observe(el);
    return () => io.disconnect();
  }, []);

  return (
    <Link ref={linkRef} href={href} className={className}>
      {children}
    </Link>
  );
}
