import matrix from '@/data/capability-matrix.json';
import Link from 'next/link';
import { CapabilityMatrixWrapper } from './capability-matrix-wrapper';
import { ConnectorBrand } from './connector-brand';

// Renders the connector × capability matrix as a horizontally-scrolling
// table. Data lives in a JSON file (`data/capability-matrix.json`) so a
// follow-up CI job can regenerate it from `defenseclaw doctor
// --capabilities --json` without touching the React component. The
// table itself is server-rendered (no client JS for the data) — only
// the outer scroll wrapper hydrates so it can attach the
// IntersectionObserver that drives the row-stagger entrance.

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
  // OpenShell sandbox support. "artifacts" means DefenseClaw renders the
  // connector's overlay-image hook files (tamperTier and hookConfig, the
  // file the harness reads its hooks from, come from its SandboxArtifacts);
  // "pending" means it renders none yet. verified says whether the harness
  // has run end to end in a sandbox; unverifiedReason says why not, and
  // untestedAuth lists the sign-in paths no live run exercised (provider
  // profile IDs, or "login" for the in-sandbox vendor login). All of it is
  // checked against internal/openshell/harness by
  // TestDocsCapabilityMatrixSandboxColumn.
  sandbox: {
    status: 'artifacts' | 'pending';
    tamperTier?: 'managed' | 'user';
    hookConfig?: string;
    harnessPin?: string;
    verified?: 'verified' | 'unverified';
    unverifiedReason?: string;
    untestedAuth?: string[];
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
          ? 'inline-flex size-5 items-center justify-center rounded-full bg-emerald-500/15 text-emerald-700 dark:text-emerald-400'
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

function Sandbox({ sandbox }: { sandbox: ConnectorRow['sandbox'] }) {
  if (sandbox.status !== 'artifacts' || !sandbox.tamperTier) {
    return <span className="text-xs text-fd-muted-foreground">pending</span>;
  }
  return (
    <>
      <span className="rounded-full bg-fd-muted px-2 py-0.5 text-xs font-medium text-fd-foreground">
        {sandbox.tamperTier} tier
      </span>
      {sandbox.hookConfig && (
        <div className="mt-1 max-w-[220px] break-all font-mono text-[11px] text-fd-muted-foreground">
          {sandbox.hookConfig}
        </div>
      )}
      {sandbox.harnessPin && (
        <div className="mt-1 text-xs text-fd-muted-foreground">image pin {sandbox.harnessPin}</div>
      )}
      {sandbox.verified && (
        <div className="mt-1 text-xs text-fd-muted-foreground">
          {sandbox.verified === 'verified' ? 'verified end to end' : 'unverified: cannot run yet'}
        </div>
      )}
    </>
  );
}

// The OpenShell sandbox harnesses in one table: image pin, tamper tier,
// the hook file in the image, and how far each harness is verified.
export function SandboxHarnessTable() {
  const rows = data.connectors.filter((c) => c.sandbox.status === 'artifacts' && c.sandbox.tamperTier);
  return (
    <CapabilityMatrixWrapper
      className="capability-matrix not-prose my-6 overflow-x-auto border border-fd-border"
      ariaLabel="OpenShell sandbox harnesses"
    >
      <table className="w-full min-w-[820px] border-collapse text-sm">
        <thead>
          <tr className="bg-fd-card text-left">
            <Th>Connector</Th>
            <Th>Image pin</Th>
            <Th>Tamper tier</Th>
            <Th>Hook config in the image</Th>
            <Th>Verification</Th>
          </tr>
        </thead>
        <tbody>
          {rows.map((c, i) => (
            <tr key={c.id} className="fd-row border-t border-fd-border" style={{ animationDelay: `${i * 35}ms` }}>
              <Td>
                <Link href={`/docs/connectors/${c.id}`} className="connector-matrix-name font-medium text-[var(--brand-cisco-strong)] hover:underline">
                  <ConnectorBrand id={c.id} size="sm" />
                  <span>{c.label}</span>
                </Link>
                <div className="connector-matrix-id text-xs text-fd-muted-foreground">{c.id}</div>
              </Td>
              <Td className="font-mono text-xs">{c.sandbox.harnessPin}</Td>
              <Td>
                <span className="rounded-full bg-fd-muted px-2 py-0.5 text-xs font-medium text-fd-foreground">
                  {c.sandbox.tamperTier}
                </span>
              </Td>
              <Td className="max-w-[240px] break-all font-mono text-[11px] text-fd-muted-foreground">{c.sandbox.hookConfig}</Td>
              <Td className="max-w-[320px] text-xs leading-relaxed">
                {c.sandbox.verified === 'verified' ? (
                  <span className="font-medium text-emerald-700 dark:text-emerald-400">Verified end to end</span>
                ) : (
                  <>
                    <span className="font-medium text-[var(--brand-cisco-strong)]">Unverified: cannot run yet.</span>{' '}
                    <span className="text-fd-muted-foreground">{c.sandbox.unverifiedReason}.</span>
                  </>
                )}
                {c.sandbox.untestedAuth && c.sandbox.untestedAuth.length > 0 && (
                  <div className="mt-1 text-fd-muted-foreground">
                    Not tested live:{' '}
                    {c.sandbox.untestedAuth.map((entry, j) => (
                      <span key={entry}>
                        {j > 0 && ', '}
                        {entry === 'login' ? 'in-sandbox login' : <code className="text-[11px]">{entry}</code>}
                      </span>
                    ))}
                  </div>
                )}
              </Td>
            </tr>
          ))}
        </tbody>
      </table>
    </CapabilityMatrixWrapper>
  );
}

export function CapabilityMatrix() {
  return (
    <CapabilityMatrixWrapper className="capability-matrix not-prose my-6 overflow-x-auto border border-fd-border">
      <table className="w-full min-w-[1000px] border-collapse text-sm">
        <thead>
          <tr className="bg-fd-card text-left">
            <Th>Connector</Th>
            <Th>Family</Th>
            <Th>Tool inspection</Th>
            <Th>Subprocess policy</Th>
            <Th>Block</Th>
            <Th>Native ask</Th>
            <Th>Fail-closed</Th>
            <Th>OpenShell sandbox</Th>
            <Th>HITL behavior</Th>
          </tr>
        </thead>
        <tbody>
          {data.connectors.map((c, i) => (
            <tr
              key={c.id}
              className="fd-row border-t border-fd-border"
              // Stagger delay matches the eye's reading cadence — fast
              // enough that the whole table settles in <500ms even for
              // a dozen connectors, slow enough that each row registers
              // as a discrete arrival.
              style={{ animationDelay: `${i * 35}ms` }}
            >
              <Td>
                <Link href={`/docs/connectors/${c.id}`} className="connector-matrix-name font-medium text-[var(--brand-cisco-strong)] hover:underline">
                  <ConnectorBrand id={c.id} size="sm" />
                  <span>{c.label}</span>
                </Link>
                <div className="connector-matrix-id text-xs text-fd-muted-foreground">{c.id}</div>
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
              <Td>
                <Sandbox sandbox={c.sandbox} />
              </Td>
              <Td className="max-w-[280px] text-xs leading-relaxed text-fd-muted-foreground">{c.hilt}</Td>
            </tr>
          ))}
        </tbody>
      </table>
    </CapabilityMatrixWrapper>
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
