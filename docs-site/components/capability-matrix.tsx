import matrix from '@/data/capability-matrix.json';

// Renders the connector × capability matrix as a horizontally-scrolling
// table. Data lives in a JSON file (`data/capability-matrix.json`) so a
// follow-up CI job can regenerate it from `defenseclaw doctor
// --capabilities --json` without touching the React component. The
// component itself is intentionally server-rendered (no client JS) so
// it ships zero runtime cost and remains fully indexable.

interface ConnectorRow {
  id: string;
  label: string;
  family: 'proxy' | 'hooks';
  toolInspection: string;
  subprocessPolicy: string;
  hooks: {
    canBlock: boolean;
    canAskNative: boolean;
    askEvents: string[];
    blockEvents: string[];
    supportsFailClosed: boolean;
    scope: 'user' | 'workspace';
  };
  hilt: string;
  notes?: string;
}

const data = matrix as { connectors: ConnectorRow[] };

function Tick({ on }: { on: boolean }) {
  return (
    <span
      aria-label={on ? 'yes' : 'no'}
      className={
        on
          ? 'inline-flex size-5 items-center justify-center rounded-full bg-emerald-500/15 text-emerald-500'
          : 'inline-flex size-5 items-center justify-center rounded-full bg-fd-muted text-fd-muted-foreground'
      }
    >
      {on ? '✓' : '·'}
    </span>
  );
}

function Family({ family }: { family: ConnectorRow['family'] }) {
  return (
    <span
      className={
        family === 'proxy'
          ? 'rounded-full bg-[var(--brand-cisco)]/15 px-2 py-0.5 text-xs font-medium text-[var(--brand-cisco-strong)]'
          : 'rounded-full bg-fd-muted px-2 py-0.5 text-xs font-medium text-fd-muted-foreground'
      }
    >
      {family}
    </span>
  );
}

export function CapabilityMatrix() {
  return (
    <div className="not-prose my-6 overflow-x-auto rounded-xl border border-fd-border">
      <table className="w-full min-w-[900px] border-collapse text-sm">
        <thead>
          <tr className="bg-fd-card text-left">
            <Th>Connector</Th>
            <Th>Family</Th>
            <Th>Tool inspection</Th>
            <Th>Subprocess policy</Th>
            <Th>Block</Th>
            <Th>Native ask</Th>
            <Th>Fail-closed</Th>
            <Th>HITL behavior</Th>
          </tr>
        </thead>
        <tbody>
          {data.connectors.map((c) => (
            <tr key={c.id} className="border-t border-fd-border">
              <Td>
                <a href={`/docs/connectors/${c.id}`} className="font-medium text-[var(--brand-cisco-strong)] hover:underline">
                  {c.label}
                </a>
                <div className="text-xs text-fd-muted-foreground">{c.id}</div>
              </Td>
              <Td>
                <Family family={c.family} />
              </Td>
              <Td>{c.toolInspection}</Td>
              <Td>{c.subprocessPolicy}</Td>
              <Td>
                <Tick on={c.hooks.canBlock} />
              </Td>
              <Td>
                <Tick on={c.hooks.canAskNative} />
                {c.hooks.askEvents.length > 0 && (
                  <div className="mt-1 text-xs text-fd-muted-foreground">
                    {c.hooks.askEvents.join(', ')}
                  </div>
                )}
              </Td>
              <Td>
                <Tick on={c.hooks.supportsFailClosed} />
              </Td>
              <Td className="max-w-[280px] text-xs leading-relaxed text-fd-muted-foreground">{c.hilt}</Td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Th({ children }: { children: React.ReactNode }) {
  return <th className="px-3 py-2 font-medium text-fd-muted-foreground">{children}</th>;
}

function Td({ children, className }: { children: React.ReactNode; className?: string }) {
  return <td className={`px-3 py-3 align-top ${className ?? ''}`}>{children}</td>;
}

export function HookEventsList({ connector }: { connector: string }) {
  const row = data.connectors.find((c) => c.id === connector);
  if (!row) return <p className="text-sm text-fd-muted-foreground">No data for {connector}</p>;
  return (
    <div className="not-prose my-4 grid gap-4 md:grid-cols-2">
      <div className="rounded-lg border border-fd-border p-4">
        <h4 className="mb-2 text-sm font-semibold">Block events</h4>
        <ul className="space-y-1 text-sm">
          {row.hooks.blockEvents.map((e) => (
            <li key={e} className="font-mono text-xs">
              {e}
            </li>
          ))}
        </ul>
      </div>
      <div className="rounded-lg border border-fd-border p-4">
        <h4 className="mb-2 text-sm font-semibold">Native ask events</h4>
        {row.hooks.askEvents.length === 0 ? (
          <p className="text-sm text-fd-muted-foreground">
            None — confirm verdicts are downgraded with the raw action preserved.
          </p>
        ) : (
          <ul className="space-y-1 text-sm">
            {row.hooks.askEvents.map((e) => (
              <li key={e} className="font-mono text-xs">
                {e}
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}
