import Script from 'next/script';

// Rendered at an old docs URL (see lib/redirects.ts). The inline script
// runs while the HTML is parsed, before the meta refresh fires, and keeps
// the query string and #anchor (a meta refresh drops them). next/script
// covers client-side navigation from a Link, where inline scripts do not
// run. The meta refresh is the no-JavaScript fallback.
export function LegacyRedirect({ to }: { to: string }) {
  const href = `${process.env.NEXT_PUBLIC_BASE_PATH ?? ''}${to}`;
  const script = `(function () {
  var target = new URL(${JSON.stringify(href)}, window.location.origin);
  target.search = window.location.search;
  target.hash = window.location.hash;
  window.location.replace(target.href);
})();`;
  return (
    <main className="mx-auto max-w-2xl px-6 py-16">
      <meta httpEquiv="refresh" content={`0; url=${href}`} />
      <script dangerouslySetInnerHTML={{ __html: script }} />
      <Script id="legacy-docs-redirect" strategy="afterInteractive" dangerouslySetInnerHTML={{ __html: script }} />
      <h1 className="text-3xl font-semibold">This page moved</h1>
      <p className="mt-4 text-fd-muted-foreground">Taking you to its new location.</p>
      <a className="mt-6 inline-flex text-fd-primary underline underline-offset-4" href={href}>
        Open the page
      </a>
    </main>
  );
}
