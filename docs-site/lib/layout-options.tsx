import type { BaseLayoutProps } from 'fumadocs-ui/layouts/shared';
import type { DocsLayoutProps } from 'fumadocs-ui/layouts/docs';
import Image from 'next/image';
import { source } from '@/lib/source';
import { site, basePath } from '@/lib/site';
import RepoStats from '@/components/repo-stats';

// Shared base options used by both the docs and home layouts. Keeps
// the navbar lockup and footer-adjacent links aligned across routes.
//
// Lockup: Cisco "bridge" mark (the same PNG asset shipped on
// cisco-ai-defense.github.io) followed by a stacked
// "Cisco / DefenseClaw" wordmark — Cisco in the foreground colour,
// DefenseClaw in the brand accent. Matches the parent project's
// visual identity so the docs site reads as part of the same family.
export const baseOptions: BaseLayoutProps = {
  nav: {
    title: (
      <span className="flex items-center gap-2.5">
        <Image
          src={`${basePath}/images/cisco-logo.png`}
          alt="Cisco"
          width={36}
          height={36}
          priority
          className="rounded-[3px]"
        />
        <span className="flex flex-col leading-none">
          <span className="text-base font-black tracking-tighter">Cisco</span>
          <span className="text-base font-black tracking-tighter text-[var(--brand-cisco-strong)]">
            {site.name}
          </span>
        </span>
      </span>
    ),
    url: '/',
  },
  // Top-right links — keep small and high-signal. The "Discord" and
  // "GitHub" entries match the README's official surfaces so users
  // hopping between project artifacts hit a consistent set.
  links: [
    {
      type: 'main',
      text: 'Docs',
      url: '/docs',
      active: 'nested-url',
    },
    {
      type: 'main',
      text: 'Connectors',
      url: '/docs/connectors',
      active: 'nested-url',
    },
    {
      type: 'main',
      text: 'Stories',
      url: '/docs/stories',
      active: 'nested-url',
    },
    // Secondary nav anchors the project to its sibling community
    // surfaces. Order is intentional: parent-org → Discord → repo
    // stats → repo. Keeping the GitHub identity (stats pills + icon)
    // adjacent at the rightmost edge so the lockup reads as a single
    // "look at the repo" affordance.
    //
    // Cisco AI Defense (parent project hub).
    {
      type: 'icon',
      text: 'Cisco AI Defense',
      label: 'Cisco AI Defense — parent project hub',
      icon: (
        // Stylised Cisco "bridge" mark in monochrome so it inherits
        // the navbar's text color in light + dark themes. Five
        // rounded bars in the canonical short-tall-tallest-tall-short
        // silhouette so it reads as Cisco at icon-button size.
        <svg viewBox="0 0 24 24" fill="currentColor" aria-hidden>
          <rect x="3" y="9" width="2" height="6" rx="1" />
          <rect x="7" y="6" width="2" height="12" rx="1" />
          <rect x="11" y="3" width="2" height="18" rx="1" />
          <rect x="15" y="6" width="2" height="12" rx="1" />
          <rect x="19" y="9" width="2" height="6" rx="1" />
        </svg>
      ),
      url: site.organization.url,
      external: true,
    },
    // Discord community. Brand-recognisable Wumpus mark in
    // currentColor; same treatment as GitHub so the icon row reads
    // as a coherent set.
    {
      type: 'icon',
      text: 'Discord',
      label: 'Discord community',
      icon: (
        <svg viewBox="0 0 24 24" fill="currentColor" aria-hidden>
          <path d="M20.317 4.3698a19.7913 19.7913 0 0 0-4.8851-1.5152.0741.0741 0 0 0-.0785.0371c-.211.3753-.4447.8648-.6083 1.2495a18.36 18.36 0 0 0-5.4868 0 12.64 12.64 0 0 0-.6177-1.2495.077.077 0 0 0-.0785-.037 19.7363 19.7363 0 0 0-4.8852 1.515.0699.0699 0 0 0-.0321.0277C.5334 9.0458-.319 13.5799.0992 18.0578a.0824.0824 0 0 0 .0312.0561 19.9034 19.9034 0 0 0 5.9929 3.0294.0777.0777 0 0 0 .0842-.0276 14.2098 14.2098 0 0 0 1.226-1.9942.076.076 0 0 0-.0416-.1057 13.1037 13.1037 0 0 1-1.8722-.8923.077.077 0 0 1-.0076-.1277c.1258-.0943.2517-.1923.3718-.2914a.0743.0743 0 0 1 .0776-.0105c3.9278 1.7933 8.18 1.7933 12.0614 0a.0739.0739 0 0 1 .0785.0095c.1202.099.246.1981.3728.2924a.077.077 0 0 1-.0066.1276 12.2986 12.2986 0 0 1-1.873.8914.0766.0766 0 0 0-.0407.1067 14.0794 14.0794 0 0 0 1.225 1.9932.076.076 0 0 0 .0842.0286 19.9591 19.9591 0 0 0 6.0023-3.0294.077.077 0 0 0 .0313-.0552c.5004-5.177-.8382-9.6739-3.5485-13.6604a.061.061 0 0 0-.0312-.0286ZM8.02 15.3312c-1.1825 0-2.1569-1.0857-2.1569-2.419 0-1.3332.9555-2.4189 2.157-2.4189 1.2108 0 2.1757 1.0952 2.1568 2.419 0 1.3332-.9555 2.4189-2.1569 2.4189Zm7.9748 0c-1.1825 0-2.1569-1.0857-2.1569-2.419 0-1.3332.9554-2.4189 2.1569-2.4189 1.2108 0 2.1757 1.0952 2.1568 2.419 0 1.3332-.946 2.4189-2.1568 2.4189Z" />
        </svg>
      ),
      url: site.repo.discord,
      external: true,
    },
    // Star + fork pills sit on the secondary side of the navbar so
    // they render directly to the left of the GitHub icon. The data
    // is fetched at build time (and refreshed on mount client-side)
    // so anonymous visitors never feel a layout shift. See
    // components/repo-stats.tsx for the fetch + caching policy.
    {
      type: 'custom',
      secondary: true,
      children: <RepoStats variant="nav" />,
    },
    {
      type: 'icon',
      text: 'GitHub',
      label: 'GitHub',
      icon: (
        <svg viewBox="0 0 24 24" fill="currentColor" aria-hidden>
          <path d="M12 .5a12 12 0 0 0-3.79 23.4c.6.11.82-.26.82-.58v-2.2c-3.34.73-4.04-1.42-4.04-1.42-.55-1.4-1.34-1.77-1.34-1.77-1.09-.74.08-.73.08-.73 1.21.09 1.85 1.24 1.85 1.24 1.07 1.84 2.81 1.31 3.5 1 .11-.78.42-1.31.76-1.61-2.66-.3-5.47-1.33-5.47-5.93 0-1.31.47-2.39 1.24-3.23-.13-.31-.54-1.55.11-3.23 0 0 1.01-.32 3.31 1.23a11.5 11.5 0 0 1 6.02 0c2.3-1.55 3.31-1.23 3.31-1.23.66 1.68.25 2.92.12 3.23.78.84 1.24 1.92 1.24 3.23 0 4.61-2.81 5.62-5.49 5.92.43.37.81 1.1.81 2.22v3.29c0 .32.22.7.83.58A12 12 0 0 0 12 .5Z" />
        </svg>
      ),
      url: site.repo.url,
      external: true,
    },
  ],
};

// DocsLayoutProps takes the same nav block but adds the source tree
// — the docs sidebar derives every entry from `meta.json` files
// under content/docs/, so authoring a new page is just dropping an
// MDX file and listing it in the local meta.
//
// We strip the `custom` repo-stats item from the docs sidebar: that
// surface renders custom link items in the main viewport (above the
// page tree) which would push the navigation down and read as
// chrome rather than content. The home navbar remains the single
// place the stats pills appear, exactly to the left of the GitHub
// icon.
export const docsOptions: DocsLayoutProps = {
  ...baseOptions,
  links: baseOptions.links?.filter((link) => link.type !== 'custom'),
  tree: source.pageTree,
};
