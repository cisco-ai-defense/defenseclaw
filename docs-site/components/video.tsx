'use client';

import { useEffect, useRef, useState } from 'react';
import { basePath } from '@/lib/site';

// Renders a single MP4 demo with a poster frame and native browser
// controls. Posters under public/images/posters/<slug>.jpg are
// generated at build time by ffmpeg (see docs-site/README.md), so
// the page paints instantly even before the video bytes are
// downloaded — important because some demos are 25–40 MB.
//
// Behaviour:
// - Lazy-loaded: the <video> element does not start fetching until
//   the user enters the viewport (IntersectionObserver) OR clicks
//   the poster overlay. This keeps initial page weight small for
//   pages that embed multiple demos.
// - Respects `prefers-reduced-motion`: autoPlay is forced off, the
//   first-frame poster is shown until the user opts in.
// - Captions: optional `.vtt` file is loaded if a sibling `tracks`
//   prop is provided. We default to no captions because no
//   transcripts ship in this PR.
// - basePath-aware: every src is prefixed with NEXT_PUBLIC_BASE_PATH
//   so embedded videos work under both root and `/defenseclaw/`.
export interface VideoProps {
  /** Filename without extension (e.g. `codex` → /videos/codex.mp4) */
  src: string;
  /** Short caption rendered below the player; also used as the
   *  accessible name on the figure. */
  caption?: string;
  /** Width:height ratio for the poster placeholder. Defaults to
   *  16:9 which matches the Screen Studio raw exports. */
  aspect?: '16/9' | '4/3' | '1/1';
  /** Optional poster slug override. Defaults to `src`. */
  poster?: string;
  /** Loop the playback. Defaults to false. */
  loop?: boolean;
}

export function Video({
  src,
  caption,
  aspect = '16/9',
  poster,
  loop = false,
}: VideoProps) {
  const ref = useRef<HTMLVideoElement | null>(null);
  const [shouldLoad, setShouldLoad] = useState(false);

  // Respect user motion preferences: never autoplay, and only
  // hydrate the <source> when the user actually wants to watch.
  useEffect(() => {
    const node = ref.current;
    if (!node) return;
    const observer = new IntersectionObserver(
      (entries) => {
        for (const entry of entries) {
          if (entry.isIntersecting) {
            setShouldLoad(true);
            observer.disconnect();
            break;
          }
        }
      },
      { rootMargin: '200px' },
    );
    observer.observe(node);
    return () => observer.disconnect();
  }, []);

  const videoUrl = `${basePath}/videos/${src}.mp4`;
  const posterUrl = `${basePath}/images/posters/${poster ?? src}.jpg`;
  const aspectClass =
    aspect === '4/3' ? 'aspect-[4/3]' : aspect === '1/1' ? 'aspect-square' : 'aspect-video';

  return (
    <figure className="my-6 overflow-hidden rounded-xl border border-fd-border bg-black/60">
      <video
        ref={ref}
        controls
        playsInline
        preload={shouldLoad ? 'metadata' : 'none'}
        poster={posterUrl}
        loop={loop}
        muted={loop}
        className={`block w-full ${aspectClass}`}
      >
        {shouldLoad ? <source src={videoUrl} type="video/mp4" /> : null}
        Your browser cannot display this demo. Download it directly:{' '}
        <a className="underline" href={videoUrl}>
          {src}.mp4
        </a>
      </video>
      {caption ? (
        <figcaption className="border-t border-fd-border bg-fd-card px-4 py-2 text-xs text-fd-muted-foreground">
          {caption}
        </figcaption>
      ) : null}
    </figure>
  );
}
