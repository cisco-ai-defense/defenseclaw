import { LitElement, html, css, nothing } from "lit";
import { customElement } from "lit/decorators.js";
import { api, type Health, type Subsystem, type SubsystemState } from "../lib/api";
import { PollController } from "../lib/poll";
import type { AuditEvent } from "../lib/audit-filter";

interface AuditCounts {
  blocked_skills: number;
  allowed_skills: number;
  blocked_mcps: number;
  allowed_mcps: number;
  alerts: number;
  total_scans: number;
  blocked_egress_calls: number;
}
interface AuditList { events: AuditEvent[]; count: number; limit: number; }

const SUBSYSTEMS: Array<[keyof Health, string]> = [
  ["api",       "API"],
  ["gateway",   "GATEWAY"],
  ["guardrail", "GUARDRAIL"],
  ["watcher",   "WATCHER"],
  ["sinks",     "SINKS"],
  ["telemetry", "TELEMETRY"],
];

function dotColor(s: SubsystemState | undefined): string {
  switch (s) {
    case "running":      return "var(--dc-clean)";
    case "starting":
    case "reconnecting":
    case "degraded":     return "var(--dc-medium)";
    case "error":
    case "stopped":      return "var(--dc-critical)";
    default:             return "var(--dc-text-faint)";
  }
}

function fmtSince(iso: string | undefined): string {
  if (!iso) return "—";
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return "—";
  const delta = Math.max(0, Date.now() - t);
  const s = Math.floor(delta / 1000);
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  return `${h}h ${m % 60}m ago`;
}

function detailLine(s: Subsystem | undefined): string {
  if (!s?.details) return "";
  const parts: string[] = [];
  for (const [k, v] of Object.entries(s.details)) {
    if (v === null || v === undefined || v === "") continue;
    parts.push(`${k}=${typeof v === "object" ? JSON.stringify(v) : String(v)}`);
  }
  return parts.join("  ");
}

@customElement("dc-overview")
export class DcOverview extends LitElement {
  static override styles = css`
    :host { display: grid; gap: var(--dc-space-4); }

    .page-header {
      display: flex;
      align-items: baseline;
      justify-content: space-between;
      gap: var(--dc-space-3);
    }
    h1 {
      font-size: var(--dc-fs-lg);
      letter-spacing: 0.18em;
      color: var(--dc-text-bright);
      margin: 0;
      text-transform: uppercase;
    }
    .subtitle {
      color: var(--dc-text-faint);
      font-size: var(--dc-fs-sm);
      letter-spacing: 0.06em;
    }

    .grid {
      display: grid;
      grid-template-columns: repeat(12, 1fr);
      gap: var(--dc-space-3);
    }
    .span-3 { grid-column: span 3; }
    .span-6 { grid-column: span 6; }
    .span-12 { grid-column: span 12; }
    @media (max-width: 1199px) {
      .span-3 { grid-column: span 6; }
      .span-6 { grid-column: span 12; }
    }
    @media (max-width: 599px) {
      .span-3 { grid-column: span 12; }
    }

    .stat .value {
      font-size: 28px;
      font-weight: 700;
      color: var(--dc-text-bright);
      letter-spacing: 0.04em;
    }
    .stat .note {
      font-size: var(--dc-fs-xs);
      color: var(--dc-text-faint);
      margin-top: var(--dc-space-1);
    }

    table {
      width: 100%;
      border-collapse: collapse;
      font-size: var(--dc-fs-sm);
    }
    th, td {
      text-align: left;
      padding: 6px 10px;
      border-bottom: 1px solid var(--dc-border);
    }
    th {
      color: var(--dc-text-faint);
      font-weight: 700;
      letter-spacing: 0.10em;
      text-transform: uppercase;
      font-size: var(--dc-fs-xs);
    }
    td.mono { color: var(--dc-text); }
    td.detail {
      color: var(--dc-text-muted);
      font-size: var(--dc-fs-xs);
    }
    .dot { display: inline-block; width: 10px; }

    .stale {
      color: var(--dc-medium);
      font-style: italic;
      font-size: var(--dc-fs-xs);
    }
    .err {
      color: var(--dc-critical);
      font-size: var(--dc-fs-sm);
    }
  `;

  private health = new PollController<Health>(
    this,
    () => api.get<Health>("/health"),
    5000,
  );
  private counts = new PollController<AuditCounts>(
    this,
    () => api.get<AuditCounts>("/v1/audit/counts"),
    30000,
  );
  private investigations = new PollController<AuditList>(
    this,
    () => api.get<AuditList>("/v1/audit?limit=20"),
    10000,
  );

  private renderInvestigationRows() {
    const events = this.investigations.state.value?.events ?? [];
    if (events.length === 0) {
      return html`<tr><td colspan="4" class="detail dc-hint">no recent events</td></tr>`;
    }
    return events.slice(0, 8).map((e) => {
      const sev = (e.severity ?? "INFO").toUpperCase();
      const ts = new Date(e.timestamp).toLocaleTimeString();
      let sevColor = "var(--dc-info)";
      if (sev === "CRITICAL") sevColor = "var(--dc-critical)";
      else if (sev === "HIGH") sevColor = "var(--dc-high)";
      else if (sev === "MEDIUM") sevColor = "var(--dc-medium)";
      else if (sev === "LOW") sevColor = "var(--dc-low)";
      return html`
        <tr>
          <td class="mono">${ts}</td>
          <td class="mono" style="color: ${sevColor};">${sev}</td>
          <td class="mono">${e.action}</td>
          <td class="detail" title=${e.target}>${e.target || "—"}</td>
        </tr>
      `;
    });
  }

  override render() {
    const h = this.health.state.value;
    const fresh = this.health.state.freshness;
    const err = this.health.state.error;
    const c = this.counts.state.value;

    return html`
      <div class="page-header">
        <div>
          <h1>// SECURITY OPERATIONS OVERVIEW</h1>
          <div class="subtitle dc-hint">
            Live governance state for OpenClaw runs, tool calls, policies, and audit evidence.
          </div>
        </div>
        <div>
          ${fresh === "stale"
            ? html`<span class="stale">stale — last fetch failed</span>`
            : fresh === "error"
            ? html`<span class="err">offline — ${err?.message ?? "unknown error"}</span>`
            : nothing}
        </div>
      </div>

      <div class="grid">
        <dc-panel class="span-3" heading="ACTIVE ALERTS" qualifier="audit store">
          <div class="stat">
            <div class="value" style="color: var(--dc-critical);">${c?.alerts ?? "—"}</div>
            <div class="note">
              ${c ? `${c.blocked_skills + c.blocked_mcps} blocked components · ${c.blocked_egress_calls} blocked egress calls` : "loading…"}
            </div>
          </div>
        </dc-panel>

        <dc-panel class="span-3" heading="GUARDRAIL" qualifier="mode">
          <div class="stat">
            <div class="value" style="color: var(--dc-accent);">
              ${h?.guardrail?.details?.["mode"] ?? "—"}
            </div>
            <div class="note">Listener ${h?.guardrail?.details?.["addr"] ?? "—"}</div>
          </div>
        </dc-panel>

        <dc-panel class="span-3" heading="SINKS" qualifier="health">
          <div class="stat">
            <div class="value" style="color: ${dotColor(h?.sinks?.state)};">
              ${h?.sinks?.state ?? "—"}
            </div>
            <div class="note">Forwarder pipeline state.</div>
          </div>
        </dc-panel>

        <dc-panel class="span-3" heading="UPTIME" qualifier="started">
          <div class="stat">
            <div class="value">${fmtSince(h?.started_at)}</div>
            <div class="note">Binary v${h?.provenance?.binary_version ?? "?"} · schema v${h?.provenance?.schema_version ?? "?"}</div>
          </div>
        </dc-panel>

        <dc-panel class="span-6" heading="SUBSYSTEMS" qualifier="from /health">
          <table>
            <thead>
              <tr><th></th><th>Subsystem</th><th>State</th><th>Since</th><th>Detail</th></tr>
            </thead>
            <tbody>
              ${SUBSYSTEMS.map(([key, label]) => {
                const s = h?.[key] as Subsystem | undefined;
                return html`
                  <tr>
                    <td><span class="dot" style="color: ${dotColor(s?.state)};">●</span></td>
                    <td class="mono">${label}</td>
                    <td class="mono">${s?.state ?? "—"}</td>
                    <td class="mono">${fmtSince(s?.since)}</td>
                    <td class="detail">${detailLine(s)}</td>
                  </tr>
                `;
              })}
            </tbody>
          </table>
        </dc-panel>

        <dc-panel class="span-6" heading="RECENT EVENTS" qualifier="last 20 from /v1/audit">
          <table>
            <thead>
              <tr><th>Time</th><th>Severity</th><th>Action</th><th>Target</th></tr>
            </thead>
            <tbody>
              ${this.renderInvestigationRows()}
            </tbody>
          </table>
        </dc-panel>

        <dc-panel class="span-12" heading="PROVENANCE" qualifier="binary identity">
          <table>
            <tbody>
              <tr>
                <td class="mono" style="color: var(--dc-text-faint); width: 200px;">binary_version</td>
                <td class="mono">${h?.provenance?.binary_version ?? "—"}</td>
              </tr>
              <tr>
                <td class="mono" style="color: var(--dc-text-faint);">schema_version</td>
                <td class="mono">${h?.provenance?.schema_version ?? "—"}</td>
              </tr>
              <tr>
                <td class="mono" style="color: var(--dc-text-faint);">content_hash</td>
                <td class="mono" style="font-size: var(--dc-fs-xs);">${h?.provenance?.content_hash ?? "—"}</td>
              </tr>
              <tr>
                <td class="mono" style="color: var(--dc-text-faint);">generation</td>
                <td class="mono">${h?.provenance?.generation ?? "—"}</td>
              </tr>
            </tbody>
          </table>
        </dc-panel>
      </div>
    `;
  }
}

declare global {
  interface HTMLElementTagNameMap { "dc-overview": DcOverview; }
}
