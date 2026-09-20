import type { Metadata } from 'next';
import Script from 'next/script';
import { canonicalUrl } from '@/lib/site';

const destinationPath = `${process.env.NEXT_PUBLIC_BASE_PATH ?? ''}/docs/policies/cel/tool-call-state/`;

const redirectScript = `
(function () {
  var target = new URL(${JSON.stringify(destinationPath)}, window.location.origin);
  target.search = window.location.search;
  target.hash = window.location.hash;
  window.location.replace(target.href);
})();
`;

export const metadata: Metadata = {
  title: 'Documentation moved',
  robots: { index: false, follow: true },
  alternates: {
    canonical: canonicalUrl('/docs/policies/cel/tool-call-state/'),
  },
};

export default function LegacyToolCallStatePage() {
  return (
    <main className="mx-auto max-w-2xl px-6 py-16">
      <Script
        id="legacy-tool-call-state-redirect"
        strategy="afterInteractive"
        dangerouslySetInnerHTML={{ __html: redirectScript }}
      />
      <h1 className="text-3xl font-semibold">Documentation moved</h1>
      <p className="mt-4 text-fd-muted-foreground">
        The tool-call state contract now lives under CEL policies.
      </p>
      <a
        className="mt-6 inline-flex text-fd-primary underline underline-offset-4"
        href={destinationPath}
      >
        Open the stateful connector lifecycle
      </a>
    </main>
  );
}
