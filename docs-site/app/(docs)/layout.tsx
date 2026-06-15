import { DocsLayout } from 'fumadocs-ui/layouts/docs';
import { docsOptions } from '@/lib/layout-options';

// Pure pass-through to the Fumadocs DocsLayout. We keep the route
// group dedicated so the docs sidebar shell is mounted exactly once
// at the docs subtree boundary; the home route group remains free to
// render a marketing layout without inheriting docs chrome.
export default function DocsRouteLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return <DocsLayout {...docsOptions}>{children}</DocsLayout>;
}
