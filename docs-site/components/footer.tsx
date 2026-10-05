import Image from 'next/image';
import Link from 'next/link';
import { site, basePath } from '@/lib/site';

// Site footer for the home layout. Columns follow the same reader path
// as the top navigation (get started, download, check support, roll
// out to a fleet), then the community surfaces. Internal links go
// through next/link so the GitHub Pages basePath is applied; external
// links are plain anchors.

interface FooterLink {
  text: string;
  href: string;
  external?: boolean;
}

interface FooterColumn {
  title: string;
  links: FooterLink[];
}

const columns: FooterColumn[] = [
  {
    title: 'Get started',
    links: [
      { text: 'What is DefenseClaw', href: '/docs/get-started/what-is-defenseclaw' },
      { text: 'Quickstart', href: '/docs/get-started/quickstart' },
      { text: 'Install', href: '/docs/get-started/install' },
      { text: 'First run', href: '/docs/get-started/first-run' },
      { text: 'Upgrade', href: '/docs/get-started/upgrade' },
    ],
  },
  {
    title: 'Download',
    links: [
      { text: 'Install commands', href: '/docs/get-started/download' },
      { text: 'Windows guide', href: '/docs/get-started/windows' },
      { text: 'Command builder', href: '/docs/command-generator' },
      { text: 'Releases', href: `${site.repo.url}/releases`, external: true },
    ],
  },
  {
    title: 'Support matrix',
    links: [
      { text: 'Connectors by OS', href: '/docs/support-matrix' },
      { text: 'Connectors', href: '/docs/connectors' },
      { text: 'Version compatibility', href: '/docs/connectors/compatibility' },
      { text: 'Capability matrix', href: '/docs/connectors/capability-matrix' },
    ],
  },
  {
    title: 'Enterprise',
    links: [
      { text: 'Deploy to a fleet', href: '/docs/enterprise/get-started' },
      { text: 'Enterprise overview', href: '/docs/enterprise' },
      { text: 'MDM guides', href: '/docs/enterprise/mdm' },
      { text: 'Machine policy', href: '/docs/enterprise/machine-policy' },
    ],
  },
  {
    title: 'Community',
    links: [
      { text: 'GitHub', href: site.repo.url, external: true },
      { text: 'Discord', href: site.repo.discord, external: true },
      { text: 'Report an issue', href: `${site.repo.url}/issues`, external: true },
      { text: 'Cisco AI Defense', href: site.organization.url, external: true },
    ],
  },
];

const linkClass =
  'text-fd-muted-foreground transition-colors hover:text-fd-foreground focus-visible:text-fd-foreground';

export function Footer() {
  return (
    <footer className="site-footer border-t border-fd-border bg-fd-card/40">
      <div className="container mx-auto grid max-w-7xl gap-10 px-4 py-12 lg:grid-cols-[minmax(14rem,1fr)_3fr] lg:gap-16">
        <div className="flex flex-col gap-4">
          <Link href="/" className="flex w-fit items-center gap-3" aria-label={`Cisco ${site.name} home`}>
            <Image
              src={`${basePath}/images/cisco-logo.png`}
              alt=""
              width={40}
              height={40}
              className="rounded-[3px]"
            />
            <span className="flex flex-col leading-none">
              <span className="text-base font-black tracking-tighter">Cisco</span>
              <span className="text-base font-black tracking-tighter text-[var(--brand-cisco-strong)]">
                {site.name}
              </span>
            </span>
          </Link>
          <p className="max-w-[18rem] text-sm leading-relaxed text-fd-muted-foreground">
            Open-source guardrails, scanning and audit evidence for AI coding agents.
          </p>
        </div>
        <nav aria-label="Footer" className="grid grid-cols-2 gap-x-6 gap-y-8 sm:grid-cols-3 lg:grid-cols-5">
          {columns.map((column) => (
            <div key={column.title}>
              <h2 className="site-footer-heading mb-3 text-xs font-semibold uppercase tracking-[0.08em] text-fd-foreground">
                {column.title}
              </h2>
              <ul className="flex flex-col gap-2 text-sm">
                {column.links.map((link) => (
                  <li key={link.text}>
                    {link.external ? (
                      <a href={link.href} rel="noreferrer" className={linkClass}>
                        {link.text}
                      </a>
                    ) : (
                      <Link href={link.href} className={linkClass}>
                        {link.text}
                      </Link>
                    )}
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </nav>
      </div>
      <div className="border-t border-fd-border">
        <p className="container mx-auto max-w-7xl px-4 py-5 text-xs text-fd-muted-foreground">
          {site.product.license} · Copyright © {site.organization.legalName} and its affiliates
        </p>
      </div>
    </footer>
  );
}
