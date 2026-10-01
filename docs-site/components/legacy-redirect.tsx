'use client';

import { useEffect } from 'react';
import { splitTarget } from '@/lib/redirects';

const basePath = process.env.NEXT_PUBLIC_BASE_PATH ?? '';

/** Site paths are exported with trailing slashes (`trailingSlash: true`). */
function withSlash(path: string): string {
  return path.endsWith('/') ? path : `${path}/`;
}

export function LegacyRedirect({ to, title }: { to: string; title: string }) {
  const { path, hash } = splitTarget(to);
  const href = `${basePath}${withSlash(path)}${hash}`;

  useEffect(() => {
    const target = new URL(`${basePath}${withSlash(path)}`, window.location.origin);
    target.search = window.location.search;
    // An incoming deep link wins; otherwise use the target's own anchor.
    target.hash = window.location.hash || hash;
    window.location.replace(target.href);
  }, [path, hash]);

  return (
    <main className="mx-auto max-w-2xl px-6 py-16">
      <h1 className="text-3xl font-semibold">This page moved</h1>
      <p className="mt-4 text-fd-muted-foreground">
        This content now lives on a different page.
      </p>
      <a
        className="mt-6 inline-flex text-fd-primary underline underline-offset-4"
        href={href}
      >
        Open {title}
      </a>
    </main>
  );
}
