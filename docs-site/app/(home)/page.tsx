import Link from 'next/link';
import { TerminalDemo } from '@/components/terminal-demo';
import { SoftwareApplicationSchema } from '@/components/structured-data';
import { Flow, Node, Edge } from '@/components/diagram/flow';
import matrix from '@/data/capability-matrix.json';

const connectors = matrix.connectors;

const STORIES = [
  {
    href: '/docs/stories/observe-claude-code',
    title: 'Stop Claude Code from running rm -rf',
    body: 'Switch action mode on, prove a destructive shell command never reaches the disk.',
  },
  {
    href: '/docs/stories/prompt-injection-codex',
    title: 'Catch a prompt injection on Codex',
    body: 'Regex packs flag the obvious; the LLM judge catches the clever ones.',
  },
  {
    href: '/docs/stories/cursor-secret-exfil',
    title: 'Block secret exfiltration from Cursor',
    body: 'Cursor’s beforeShellExecution hook is the stop point. We scan, then ask before it runs.',
  },
  {
    href: '/docs/stories/hitl-approvals',
    title: 'Approve risky tool calls before they fire',
    body: 'HITL sits between observe and enforcement. Pause, review, then continue.',
  },
  {
    href: '/docs/stories/local-observability',
    title: 'Pin local observability in under 60 seconds',
    body: 'One command brings up Prometheus, Loki, Tempo, and Grafana — pre-wired to the gateway.',
  },
  {
    href: '/docs/stories/switch-connectors',
    title: 'Switch from OpenClaw to Codex without losing audit history',
    body: 'The audit DB is connector-agnostic. Setup rewires the data path; nothing else moves.',
  },
];

const MODES = [
  {
    name: 'Observe',
    mark: 'O',
    tagline: 'See what your agent does. Block nothing.',
    body: 'Findings stream to the audit DB and your sinks. Run it for a week before enforcement.',
  },
  {
    name: 'Action',
    mark: 'A',
    tagline: 'Block on HIGH and CRITICAL.',
    body: 'CRITICAL findings always block. HIGH findings block unless HITL pauses them for review.',
  },
  {
    name: 'HITL',
    mark: 'H',
    tagline: 'Pause, review, then continue.',
    body: 'Reaches the operator via the connector’s native ask, or downgrades to a TUI prompt.',
  },
];

// Compact landing-page summary of the audit fan-out — same names that
// appear in the connector docs, kept as a chip strip so it scans in
// under a second instead of forcing the visitor through a sentence.
const AUDIT_SINKS = ['SQLite', 'JSONL', 'OTLP', 'Splunk', 'Webhooks'];

const WORKFLOW = ['Observe', 'Action', 'HITL'];

// First sentence of c.notes is enough on the landing page; the full
// sentence runs onto a second line and dilutes the card's job (point
// at the dedicated connector page). Defensive split — falls back to
// the full string if the data ever lacks a period.
function firstSentence(text: string): string {
  const idx = text.indexOf('. ');
  return idx === -1 ? text : `${text.slice(0, idx)}.`;
}

export default function HomePage() {
  return (
    <main className="flex flex-1 flex-col">
      <SoftwareApplicationSchema />

      {/* Hero */}
      <section className="relative isolate overflow-hidden border-b border-fd-border">
        <div
          aria-hidden
          className="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_at_top,_var(--brand-cisco)/0.12,_transparent_55%),radial-gradient(ellipse_at_bottom_left,_var(--brand-warn)/0.07,_transparent_60%)]"
        />
        <div aria-hidden className="hero-grain pointer-events-none absolute inset-0" />

        {/* `min-w-0` on the grid + each cell prevents the right column
            (the terminal `<pre overflow-x-auto>`) from forcing the whole
            grid wider than the viewport on narrow phones (≤390px). The
            `w-full` clamp on cells keeps every chip row, CTA strip, and
            paragraph honoring the parent width once min-width is zero. */}
        <div className="container relative mx-auto grid min-w-0 max-w-7xl gap-10 px-4 py-16 lg:grid-cols-2 lg:gap-16 lg:py-24">
          <div className="flex w-full min-w-0 flex-col justify-center gap-6">
            <span className="inline-flex w-fit items-center gap-2 rounded-full border border-[var(--brand-cisco)]/30 bg-[var(--brand-cisco)]/10 px-3 py-1 text-xs font-medium uppercase tracking-wider text-[var(--brand-cisco-strong)]">
              <span aria-hidden className="size-1.5 rounded-full bg-[var(--brand-cisco)]" />
              Official Cisco project · Apache-2.0
            </span>
            <h1 className="text-balance wrap-break-word text-4xl font-bold tracking-tight md:text-5xl lg:text-6xl">
              Security governance for{' '}
              <span className="text-[var(--brand-cisco-strong)]">OpenClaw</span> and agentic AI
              runtimes.
            </h1>
            <p className="max-w-xl text-pretty text-lg text-fd-muted-foreground">
              DefenseClaw inspects every prompt, completion, and tool call your AI coding agent
              makes — block, approve, or audit, per connector.
            </p>
            <div className="flex flex-wrap items-center gap-3">
              <Link
                href="/docs/get-started/quickstart"
                className="inline-flex items-center gap-2 rounded-md bg-[var(--brand-cisco)] px-4 py-2 text-sm font-medium text-white shadow-md transition hover:bg-[var(--brand-cisco-strong)]"
              >
                Quickstart
                <span aria-hidden>→</span>
              </Link>
              <Link
                href="/docs/setup/guardrail"
                className="inline-flex items-center gap-2 rounded-md border border-fd-border bg-fd-card px-4 py-2 text-sm font-medium transition hover:bg-fd-muted"
              >
                Setup Guardrail
              </Link>
              <Link
                href="/docs/capability-matrix"
                className="inline-flex items-center gap-2 rounded-md px-4 py-2 text-sm font-medium text-fd-muted-foreground transition hover:text-fd-foreground"
              >
                Capability Matrix
              </Link>
            </div>

            {/* Three chip strips replace the previous prose bullets. They
                cover the same ground (connectors / workflow / audit
                fan-out) but compress the read time from "scan three
                long sentences" to "scan three rows of pills". The
                visual vocabulary mirrors the navbar repo-stats pills
                so the lockup reads as one design system. */}
            <div className="mt-2 flex flex-col gap-3">
              <HeroChipRow label="Connectors">
                {connectors.map((c) => (
                  <HeroChip key={c.id}>
                    <span
                      aria-hidden
                      className={
                        c.family === 'proxy'
                          ? 'size-1.5 rounded-full bg-[var(--brand-cisco)]'
                          : 'size-1.5 rounded-full bg-fd-muted-foreground/40'
                      }
                    />
                    {c.label}
                  </HeroChip>
                ))}
              </HeroChipRow>
              <HeroChipRow label="Workflow">
                {WORKFLOW.map((w, i) => (
                  <span key={w} className="inline-flex items-center gap-1.5">
                    <HeroChip>{w}</HeroChip>
                    {i < WORKFLOW.length - 1 && (
                      <span aria-hidden className="text-fd-muted-foreground/60">
                        →
                      </span>
                    )}
                  </span>
                ))}
              </HeroChipRow>
              <HeroChipRow label="Audit">
                {AUDIT_SINKS.map((s) => (
                  <HeroChip key={s}>{s}</HeroChip>
                ))}
              </HeroChipRow>
            </div>
          </div>

          {/* The terminal pre uses overflow-x-auto, but it can only scroll
              inside its own box if the grid cell honors min-width:0.
              Without `min-w-0` here the long install curl line pushes
              the grid track wider than the viewport on phones. */}
          <div className="flex w-full min-w-0 items-center">
            <TerminalDemo />
          </div>
        </div>
      </section>

      {/* Three modes */}
      <section className="container mx-auto max-w-7xl px-4 py-16">
        <div className="mb-8 flex flex-col gap-2">
          <p className="text-sm font-medium uppercase tracking-wider text-[var(--brand-cisco-strong)]">
            Three modes, one command
          </p>
          <h2 className="text-3xl font-semibold tracking-tight">
            Start in observe. Earn enforcement.
          </h2>
          <p className="max-w-2xl text-fd-muted-foreground">
            Start in observe. Promote to action when the policy is tuned. Layer HITL on top for
            CRITICAL findings.
          </p>
        </div>
        <div className="grid gap-4 md:grid-cols-3">
          {MODES.map((m) => (
            <article
              key={m.name}
              className="rounded-xl border border-fd-border bg-fd-card/40 p-6 transition hover:border-[var(--brand-cisco)]/50"
            >
              <div className="flex items-center gap-3">
                {/* Single-letter mark mirrors the chip language used in
                    the hero so the cards feel like part of the same
                    system rather than a separate component island. */}
                <span
                  aria-hidden
                  className="inline-flex size-7 items-center justify-center rounded-full border border-fd-border bg-fd-card text-xs font-semibold text-[var(--brand-cisco-strong)]"
                >
                  {m.mark}
                </span>
                <h3 className="text-xl font-semibold">{m.name}</h3>
              </div>
              <p className="mt-3 text-sm font-medium text-[var(--brand-cisco-strong)]">{m.tagline}</p>
              <p className="mt-2 text-sm text-fd-muted-foreground">{m.body}</p>
            </article>
          ))}
        </div>
      </section>

      {/* Connector grid */}
      <section className="border-t border-fd-border bg-fd-card/30 py-16">
        <div className="container mx-auto max-w-7xl px-4">
          <div className="mb-8 flex flex-col gap-2">
            <p className="text-sm font-medium uppercase tracking-wider text-[var(--brand-cisco-strong)]">
              Connectors
            </p>
            <h2 className="text-3xl font-semibold tracking-tight">
              One adapter per agent. Same enforcement contract.
            </h2>
            <p className="max-w-2xl text-fd-muted-foreground">
              Proxy connectors intercept LLM traffic. Hook connectors wire into the agent’s
              native lifecycle.
            </p>
          </div>
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {connectors.map((c) => (
              <Link
                key={c.id}
                href={`/docs/connectors/${c.id}`}
                className="group rounded-xl border border-fd-border bg-fd-card p-5 transition hover:border-[var(--brand-cisco)]/50"
              >
                <div className="mb-3 flex items-center justify-between gap-2">
                  <span className="text-base font-semibold">{c.label}</span>
                  {/* Family badge dot matches the hero chip dots so the
                      proxy/hooks distinction reads identically across
                      both surfaces. */}
                  <span className="inline-flex items-center gap-1.5 rounded-full border border-fd-border bg-fd-secondary/50 px-2 py-0.5 text-[11px] font-medium text-fd-muted-foreground">
                    <span
                      aria-hidden
                      className={
                        c.family === 'proxy'
                          ? 'size-1.5 rounded-full bg-[var(--brand-cisco)]'
                          : 'size-1.5 rounded-full bg-fd-muted-foreground/40'
                      }
                    />
                    {c.family}
                  </span>
                </div>
                <p className="text-sm text-fd-muted-foreground">{firstSentence(c.notes)}</p>
                <p className="mt-3 text-sm font-medium text-[var(--brand-cisco-strong)] opacity-70 transition group-hover:opacity-100 group-hover:underline">
                  Open page →
                </p>
              </Link>
            ))}
          </div>
        </div>
      </section>

      {/* Architecture */}
      <section className="container mx-auto max-w-7xl px-4 py-16">
        <div className="mb-6 flex flex-col gap-2">
          <p className="text-sm font-medium uppercase tracking-wider text-[var(--brand-cisco-strong)]">
            Architecture
          </p>
          <h2 className="text-3xl font-semibold tracking-tight">A Python CLI, a Go sidecar, and one OpenClaw plugin.</h2>
        </div>
        {/* Replaces the previous ASCII <pre> with the same diagram
            primitive every docs page uses, so the gateway, policy, and
            audit fan-out all share the visual vocabulary readers see
            once they click through. */}
        <Flow
          direction="LR"
          caption="The connector talks to the gateway over a stable Go interface; the gateway fans out to scanners, the LLM provider, and audit sinks."
        >
          <Node id="agent" kind="agent">
            Agent runtime
          </Node>
          <Node id="connector" kind="connector">
            DefenseClaw connector
          </Node>
          <Node id="gateway" kind="gateway">
            defenseclaw-gateway
          </Node>
          <Node id="policy" kind="policy">
            {`Policy + scanners\n+ audit`}
          </Node>
          <Node id="llm" kind="generic">
            LLM provider
          </Node>
          <Node id="sinks" kind="datastore">
            {`OTLP / Splunk\nwebhooks / JSONL`}
          </Node>
          <Edge from="agent" to="connector" />
          <Edge from="connector" to="gateway" />
          <Edge from="gateway" to="policy" label="inspect" />
          <Edge from="gateway" to="llm" label="guardrail proxy" />
          <Edge from="gateway" to="sinks" label="audit" />
        </Flow>
        <p className="mt-3 text-sm text-fd-muted-foreground">
          Python CLI for setup. Go gateway for inspection and audit. TypeScript plugin closes the
          loop on the agent side.
        </p>
      </section>

      {/* Stories */}
      <section className="border-t border-fd-border bg-fd-card/30 py-16">
        <div className="container mx-auto max-w-7xl px-4">
          <div className="mb-8 flex flex-col gap-2">
            <p className="text-sm font-medium uppercase tracking-wider text-[var(--brand-cisco-strong)]">
              Stories
            </p>
            <h2 className="text-3xl font-semibold tracking-tight">
              Six things you can do today.
            </h2>
          </div>
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
            {STORIES.map((s) => (
              <Link
                key={s.href}
                href={s.href}
                className="group rounded-xl border border-fd-border bg-fd-card p-5 transition hover:border-[var(--brand-cisco)]/50"
              >
                <h3 className="text-base font-semibold">{s.title}</h3>
                <p className="mt-2 text-sm text-fd-muted-foreground">{s.body}</p>
                {/* "Read →" is muted at rest so the card body reads as
                    the primary content; on hover it brightens and
                    underlines as the click affordance. */}
                <p className="mt-3 text-sm font-medium text-[var(--brand-cisco-strong)] opacity-70 transition group-hover:opacity-100 group-hover:underline">
                  Read →
                </p>
              </Link>
            ))}
          </div>
        </div>
      </section>

      {/* CTA */}
      <section className="container mx-auto max-w-3xl px-4 py-20 text-center">
        <h2 className="text-balance text-3xl font-semibold tracking-tight md:text-4xl">
          Ready to put a guardrail around your agent?
        </h2>
        <p className="mt-4 text-fd-muted-foreground">
          Five minutes. No LLM key required.
        </p>
        <div className="mt-6 flex flex-wrap justify-center gap-3">
          <Link
            href="/docs/get-started/install"
            className="inline-flex items-center gap-2 rounded-md bg-[var(--brand-cisco)] px-5 py-2.5 text-sm font-medium text-white shadow-md transition hover:bg-[var(--brand-cisco-strong)]"
          >
            Install DefenseClaw
          </Link>
          <Link
            href="/docs/setup/guardrail"
            className="inline-flex items-center gap-2 rounded-md border border-fd-border bg-fd-card px-5 py-2.5 text-sm font-medium transition hover:bg-fd-muted"
          >
            Setup Guardrail
          </Link>
        </div>
      </section>
    </main>
  );
}

// Hero chip primitives — kept co-located because they exist solely to
// give the hero left column three scannable rows. Sharing one
// `HeroChip` ensures the connector dots, the workflow pills, and the
// audit sinks all read with identical weight. The styling tokens
// (rounded-full, bg-fd-secondary/50, border-fd-border, text-xs) match
// the navbar repo-stats pills so the lockup reads as one system.
function HeroChipRow({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <div className="flex flex-col gap-1.5 sm:flex-row sm:items-center sm:gap-3">
      <span className="text-[11px] font-semibold uppercase tracking-wider text-fd-muted-foreground/70 sm:w-20 sm:shrink-0">
        {label}
      </span>
      <div className="flex flex-wrap items-center gap-1.5">{children}</div>
    </div>
  );
}

function HeroChip({ children }: { children: React.ReactNode }) {
  return (
    <span className="inline-flex items-center gap-1.5 rounded-full border border-fd-border bg-fd-secondary/50 px-2.5 py-0.5 text-xs text-fd-muted-foreground">
      {children}
    </span>
  );
}
