import matrix from '@/data/capability-matrix.json';
import Link from 'next/link';
import { Fragment } from 'react';
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

// Yes/No as words, not a tick and a dot: a lone dot read as "unknown" or
// "not applicable" to reviewers. The colour only reinforces the word.
function Tick({ on }: { on: boolean }) {
  return (
    <span
      className={
        on
          ? 'inline-flex items-center gap-1 rounded-full bg-emerald-500/15 px-2 py-0.5 text-xs font-medium text-emerald-800 dark:text-emerald-300'
          : 'inline-flex items-center gap-1 rounded-full border border-fd-border px-2 py-0.5 text-xs font-medium text-fd-muted-foreground'
      }
    >
      <span aria-hidden="true">{on ? '✓' : '✕'}</span>
      {on ? 'Yes' : 'No'}
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

// The main matrix shows only the tier and whether the harness is verified.
// The image pin and the hook file live in SandboxHarnessTable, so the wide
// matrix doesn't repeat them.
function Sandbox({ sandbox }: { sandbox: ConnectorRow['sandbox'] }) {
  if (sandbox.status !== 'artifacts' || !sandbox.tamperTier) {
    return <span className="text-xs text-fd-muted-foreground">pending</span>;
  }
  return (
    <>
      <span className="whitespace-nowrap rounded-full bg-fd-muted px-2 py-0.5 text-xs font-medium text-fd-foreground">
        {sandbox.tamperTier} tier
      </span>
      {sandbox.verified && (
        <div className="mt-1 text-xs text-fd-muted-foreground">
          {sandbox.verified === 'verified' ? 'verified end to end' : 'unverified: cannot run yet'}
        </div>
      )}
    </>
  );
}

// Legend for the Yes/No cells, shown above the matrix.
function CapabilityMatrixLegend() {
  return (
    <p className="not-prose mt-6 flex flex-wrap items-center gap-x-4 gap-y-2 text-sm text-fd-muted-foreground">
      <span className="inline-flex items-center gap-2">
        <Tick on /> the connector supports it
      </span>
      <span className="inline-flex items-center gap-2">
        <Tick on={false} /> it doesn&apos;t
      </span>
      <span>Scroll the table sideways on a narrow screen.</span>
    </p>
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
    <>
    <CapabilityMatrixLegend />
    <CapabilityMatrixWrapper className="capability-matrix not-prose mb-6 mt-3 overflow-x-auto border border-fd-border">
      <table className="w-full min-w-[760px] border-collapse text-sm">
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
          </tr>
        </thead>
        <tbody>
          {data.connectors.map((c, i) => (
            <Fragment key={c.id}>
            <tr
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
              <Td className="min-w-[104px] text-xs leading-relaxed">{c.toolInspection}</Td>
              <Td className="text-xs leading-relaxed">{c.subprocessPolicy}</Td>
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
            </tr>
            {/* HITL behaviour is prose, so it gets its own full-width line
                under the connector instead of a ninth, very wide column. */}
            <tr className="fd-row" style={{ animationDelay: `${i * 35}ms` }}>
              <td colSpan={8} className="px-2.5 pb-3 pt-0 text-xs leading-relaxed text-fd-muted-foreground">
                <span className="font-medium text-fd-foreground">HITL: </span>
                {c.hilt}
              </td>
            </tr>
            </Fragment>
          ))}
        </tbody>
      </table>
    </CapabilityMatrixWrapper>
    </>
  );
}

function Th({ children }: { children: React.ReactNode }) {
  return <th className="px-2.5 py-2 font-medium text-fd-muted-foreground">{children}</th>;
}

function Td({ children, className }: { children: React.ReactNode; className?: string }) {
  return <td className={`px-2.5 py-3 align-top ${className ?? ''}`}>{children}</td>;
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
