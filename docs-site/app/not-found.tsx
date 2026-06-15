import Link from 'next/link';

export default function NotFound() {
  return (
    <main className="container mx-auto flex max-w-2xl flex-1 flex-col items-center justify-center gap-6 px-4 py-32 text-center">
      <span className="rounded-full border border-[var(--brand-cisco)]/30 bg-[var(--brand-cisco)]/10 px-3 py-1 text-xs font-medium uppercase tracking-wider text-[var(--brand-cisco-strong)]">
        404
      </span>
      <h1 className="text-balance text-4xl font-semibold tracking-tight md:text-5xl">
        That page is not in the audit log.
      </h1>
      <p className="text-fd-muted-foreground">
        Looks like you followed a stale link. Try the docs index or the Setup Guardrail flow —
        those are the high-traffic surfaces.
      </p>
      <div className="flex flex-wrap justify-center gap-3">
        <Link
          href="/docs"
          className="inline-flex items-center gap-2 rounded-md bg-[var(--brand-cisco)] px-4 py-2 text-sm font-medium text-white shadow-md transition hover:bg-[var(--brand-cisco-strong)]"
        >
          Open the docs
        </Link>
        <Link
          href="/docs/setup/guardrail"
          className="inline-flex items-center gap-2 rounded-md border border-fd-border bg-fd-card px-4 py-2 text-sm font-medium transition hover:bg-fd-muted"
        >
          Setup Guardrail
        </Link>
      </div>
    </main>
  );
}
