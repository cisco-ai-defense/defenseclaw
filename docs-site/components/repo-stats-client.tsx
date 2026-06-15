'use client';

import { useEffect, useRef, useState } from 'react';
import { formatCount, githubApiUrl, type RepoStats } from '@/lib/github-stats';

// Single-shot count-up that animates from 0 → target in ~600ms on
// initial client mount. Reduced-motion users skip the animation. The
// `aria-label` on the wrapping pill always reflects the final number,
// so assistive tech never sees the in-progress animation.
//
// Subsequent updates (e.g. the GitHub API refresh) just snap to the
// new value — we don't re-animate, because that would make the navbar
// numbers count up *twice* in normal use.
function CountUp({ value }: { value: number }) {
  const [display, setDisplay] = useState(value);
  const fromRef = useRef(0);
  const animatedRef = useRef(false);
  const rafRef = useRef<number | null>(null);

  useEffect(() => {
    // First mount only: animate 0 → value. After that any value
    // change is treated as a real update (API refresh) and snaps.
    if (animatedRef.current) {
      setDisplay(value);
      return;
    }

    const reduced = window.matchMedia(
      '(prefers-reduced-motion: reduce)',
    ).matches;
    if (reduced) {
      animatedRef.current = true;
      setDisplay(value);
      return;
    }

    animatedRef.current = true;
    const start = performance.now();
    const duration = 600;
    const from = fromRef.current;
    const to = value;
    const tick = (now: number) => {
      const t = Math.min(1, (now - start) / duration);
      // Ease-out cubic so the number settles smoothly into place
      // rather than slamming into the final value.
      const eased = 1 - Math.pow(1 - t, 3);
      setDisplay(Math.round(from + (to - from) * eased));
      if (t < 1) {
        rafRef.current = requestAnimationFrame(tick);
      }
    };
    rafRef.current = requestAnimationFrame(tick);

    return () => {
      if (rafRef.current !== null) {
        cancelAnimationFrame(rafRef.current);
      }
    };
  }, [value]);

  return <>{formatCount(display)}</>;
}

export type RepoStatsVariant = 'banner' | 'nav';

interface Props {
  initial: RepoStats | null;
  // 'banner' — pills tuned for the rainbow banner (white-on-color).
  // 'nav'    — themed pills sitting beside the GitHub icon in the
  //            navbar; uses fumadocs CSS variables so the lockup
  //            reads correctly in both light and dark themes.
  variant?: RepoStatsVariant;
}

// Renders the star + fork pills. Hydrates with the build-time numbers
// (so the markup is identical across SSR/CSR), then refreshes once on
// mount from the public GitHub API to surface the current count between
// deploys. Anonymous calls share the visitor's 60/hr quota — we
// silently keep the build-time numbers if the request fails or is
// rate-limited.
export default function RepoStatsClient({ initial, variant = 'banner' }: Props) {
  const [stats, setStats] = useState<RepoStats | null>(initial);

  useEffect(() => {
    let cancelled = false;

    const refresh = async () => {
      try {
        const res = await fetch(githubApiUrl, {
          headers: {
            Accept: 'application/vnd.github+json',
            'X-GitHub-Api-Version': '2022-11-28',
          },
          // Defense-in-depth: bound the request so a slow API call
          // can't keep this component fetching forever.
          signal: AbortSignal.timeout(5000),
        });
        if (!res.ok) {
          return;
        }
        const json = (await res.json()) as {
          stargazers_count?: number;
          forks_count?: number;
        };
        if (
          cancelled ||
          typeof json.stargazers_count !== 'number' ||
          typeof json.forks_count !== 'number'
        ) {
          return;
        }
        setStats({
          stars: json.stargazers_count,
          forks: json.forks_count,
        });
      } catch {
        // Ignore — keep whatever we rendered with.
      }
    };

    void refresh();

    return () => {
      cancelled = true;
    };
  }, []);

  if (!stats) {
    return null;
  }

  const isNav = variant === 'nav';
  // Pill styling switches per variant. The banner sits on the rainbow
  // gradient (high-contrast white surface), so we use translucent
  // white. The navbar variant sits on the themed background, so it
  // pulls from fumadocs's secondary token to stay legible in light
  // and dark modes without baking in either palette.
  const containerClass = isNav
    ? 'inline-flex items-center gap-1 align-middle text-xs font-medium text-fd-muted-foreground'
    : 'ml-2 inline-flex items-center gap-1.5 align-middle';
  const pillClass = isNav
    ? 'inline-flex items-center gap-1 rounded-full border border-fd-border bg-fd-secondary/60 px-2 py-0.5 leading-none'
    : 'inline-flex items-center gap-1 rounded-full bg-white/15 px-2 py-0.5 leading-none';

  return (
    <span className={containerClass}>
      <span
        aria-label={`${stats.stars.toLocaleString('en-US')} stars on GitHub`}
        title={`${stats.stars.toLocaleString('en-US')} stars`}
        className={pillClass}
      >
        <svg
          aria-hidden
          width="11"
          height="11"
          viewBox="0 0 16 16"
          fill="currentColor"
        >
          <path d="M8 .25a.75.75 0 0 1 .673.418l1.882 3.815 4.21.612a.75.75 0 0 1 .416 1.279l-3.046 2.97.719 4.192a.75.75 0 0 1-1.088.791L8 12.347l-3.766 1.98a.75.75 0 0 1-1.088-.79l.72-4.193L.818 6.374a.75.75 0 0 1 .416-1.28l4.21-.611L7.327.668A.75.75 0 0 1 8 .25Z" />
        </svg>
        <span className="tabular-nums">
          <CountUp value={stats.stars} />
        </span>
      </span>
      <span
        aria-label={`${stats.forks.toLocaleString('en-US')} forks on GitHub`}
        title={`${stats.forks.toLocaleString('en-US')} forks`}
        className={pillClass}
      >
        <svg
          aria-hidden
          width="11"
          height="11"
          viewBox="0 0 16 16"
          fill="currentColor"
        >
          <path d="M5 5.372v.878c0 .414.336.75.75.75h4.5a.75.75 0 0 0 .75-.75v-.878a2.25 2.25 0 1 1 1.5 0v.878a2.25 2.25 0 0 1-2.25 2.25h-1.5v2.128a2.251 2.251 0 1 1-1.5 0V8.5h-1.5A2.25 2.25 0 0 1 3.5 6.25v-.878a2.25 2.25 0 1 1 1.5 0ZM5 3.25a.75.75 0 1 0-1.5 0 .75.75 0 0 0 1.5 0Zm6.75.75a.75.75 0 1 0 0-1.5.75.75 0 0 0 0 1.5Zm-3 8.75a.75.75 0 1 0-1.5 0 .75.75 0 0 0 1.5 0Z" />
        </svg>
        <span className="tabular-nums">
          <CountUp value={stats.forks} />
        </span>
      </span>
    </span>
  );
}
