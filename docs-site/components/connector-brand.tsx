import type { CSSProperties } from 'react';
import matrix from '@/data/capability-matrix.json';

type ConnectorBrandSize = 'sm' | 'md';

interface OfficialConnectorIcon {
  /** Local copy from @lobehub/icons-static-svg. */
  src: string;
  /** Accent used by the surrounding brand tile, not a substitute logo. */
  accent: string;
  /** Monochrome SVGs need a light foreground in dark mode. */
  monochrome?: boolean;
}

// These filenames are intentionally connector IDs. The source SVGs live in
// public/connector-icons and are copied from LobeHub's official static package
// so the exported docs never depend on a third-party CDN.
const OFFICIAL_ICONS: Partial<Record<string, OfficialConnectorIcon>> = {
  openclaw: { src: 'openclaw.svg', accent: '#ff4d4d' },
  claudecode: { src: 'claudecode.svg', accent: '#d97757' },
  codex: { src: 'codex.svg', accent: '#10a37f' },
  cursor: { src: 'cursor.svg', accent: '#57636d', monochrome: true },
  windsurf: { src: 'windsurf.svg', accent: '#0b86aa', monochrome: true },
  geminicli: { src: 'geminicli.svg', accent: '#4285f4' },
  copilot: { src: 'copilot.svg', accent: '#7657d6', monochrome: true },
  openhands: { src: 'openhands.svg', accent: '#16a34a' },
  antigravity: { src: 'antigravity.svg', accent: '#7767e8' },
  hermes: { src: 'hermes.svg', accent: '#ad7a1f', monochrome: true },
  opencode: { src: 'opencode.svg', accent: '#52616b', monochrome: true },
};

const FALLBACKS: Record<string, { initials: string; color: string }> = {
  zeptoclaw: { initials: 'ZC', color: '#7c5ce7' },
  omnigent: { initials: 'OG', color: '#cc4b9a' },
};

const labels = new Map(matrix.connectors.map((connector) => [connector.id, connector.label]));
const basePath = process.env.NEXT_PUBLIC_BASE_PATH ?? '';

interface ConnectorBrandProps {
  id: string;
  size?: ConnectorBrandSize;
}

export function ConnectorBrand({ id, size = 'md' }: ConnectorBrandProps) {
  const icon = OFFICIAL_ICONS[id];
  const fallback = FALLBACKS[id];
  const label = labels.get(id) ?? id;
  const color = icon?.accent ?? fallback?.color ?? '#006f9d';
  const style = { '--connector-brand': color } as CSSProperties;

  return (
    <span
      aria-hidden
      className="connector-brand-mark"
      data-size={size}
      data-monochrome={icon?.monochrome ? 'true' : undefined}
      style={style}
      title={`${label} brand mark`}
    >
      {icon ? (
        <img
          alt=""
          decoding="async"
          height="24"
          loading="lazy"
          src={`${basePath}/connector-icons/${icon.src}`}
          width="24"
        />
      ) : (
        <span className="connector-brand-fallback">{fallback?.initials ?? label.slice(0, 2)}</span>
      )}
    </span>
  );
}

export function ConnectorLabel({ id }: { id: string }) {
  return (
    <span className="connector-label">
      <ConnectorBrand id={id} size="sm" />
      <span>{labels.get(id) ?? id}</span>
    </span>
  );
}
