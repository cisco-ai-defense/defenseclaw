import Image from 'next/image';
import { site, basePath } from '@/lib/site';

export function Footer() {
  return (
    <footer className="border-t border-fd-border bg-fd-card/40 py-10">
      <div className="container mx-auto flex max-w-7xl flex-col gap-6 px-4 md:flex-row md:items-center md:justify-between">
        <div className="flex items-center gap-3">
          <Image
            src={`${basePath}/images/cisco-logo.png`}
            alt="Cisco"
            width={40}
            height={40}
            className="rounded-[3px]"
          />
          <div>
            <p className="flex items-baseline gap-1.5 text-sm font-semibold">
              <span>Cisco</span>
              <span className="text-[var(--brand-cisco-strong)]">{site.name}</span>
            </p>
            <p className="text-xs text-fd-muted-foreground">
              Apache-2.0 · Copyright © Cisco Systems, Inc. and its affiliates
            </p>
          </div>
        </div>
        <nav aria-label="Footer">
          <ul className="flex flex-wrap gap-x-5 gap-y-2 text-sm">
            <li>
              <a
                href="/docs"
                className="text-fd-muted-foreground transition hover:text-fd-foreground"
              >
                Documentation
              </a>
            </li>
            <li>
              <a
                href="/docs/setup/guardrail"
                className="text-fd-muted-foreground transition hover:text-fd-foreground"
              >
                Setup Guardrail
              </a>
            </li>
            <li>
              <a
                href="/docs/capability-matrix"
                className="text-fd-muted-foreground transition hover:text-fd-foreground"
              >
                Capability Matrix
              </a>
            </li>
            <li>
              <a
                href={site.repo.url}
                rel="noreferrer"
                className="text-fd-muted-foreground transition hover:text-fd-foreground"
              >
                GitHub
              </a>
            </li>
            <li>
              <a
                href={site.repo.discord}
                rel="noreferrer"
                className="text-fd-muted-foreground transition hover:text-fd-foreground"
              >
                Discord
              </a>
            </li>
            <li>
              <a
                href={site.organization.url}
                rel="noreferrer"
                className="text-fd-muted-foreground transition hover:text-fd-foreground"
              >
                Cisco AI Security
              </a>
            </li>
          </ul>
        </nav>
      </div>
    </footer>
  );
}
