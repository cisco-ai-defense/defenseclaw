import type { CSSProperties } from 'react';
import matrix from '@/data/capability-matrix.json';
import {
  connectorIconDefinitions,
  type ConnectorIconDefinition,
} from '@/data/connector-icons';

type ConnectorBrandSize = 'sm' | 'md';

// These filenames are intentionally connector IDs. The source SVGs live in
// public/connector-icons and are copied from LobeHub's official static package
// so the exported docs never depend on a third-party CDN.
const OFFICIAL_ICONS: Partial<Record<string, ConnectorIconDefinition>> = connectorIconDefinitions;

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
          src={`${basePath}/connector-icons/${icon.target}`}
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
