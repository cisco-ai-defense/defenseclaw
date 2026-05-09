import { LitElement, html, css, nothing } from "lit";
import { customElement, state } from "lit/decorators.js";
import { api } from "../lib/api";
import { PollController } from "../lib/poll";
import { parseFilter, applyFilter, type AuditEvent } from "../lib/audit-filter";

interface AuditResponse {
  events: AuditEvent[];
  count: number;
  limit: number;
}

const SEV_CLASS: Record<string, string> = {
  CRITICAL: "critical",
  HIGH:     "high",
  MEDIUM:   "medium",
  LOW:      "low",
  INFO:     "info",
};

@customElement("dc-audit")
export class DcAudit extends LitElement {
  static override styles = css`
    :host { display: grid; grid-template-rows: auto auto minmax(0,1fr); gap: var(--dc-space-3); height: 100%; min-height: 0; }

    .header {
      display: flex;
      align-items: baseline;
      justify-content: space-between;
      gap: var(--dc-space-3);
    }
    h1 {
      margin: 0;
      font-size: var(--dc-fs-lg);
      letter-spacing: 0.18em;
      color: var(--dc-text-bright);
      text-transform: uppercase;
    }
    .subtitle { color: var(--dc-text-faint); font-size: var(--dc-fs-sm); }

    .filter-bar {
      display: grid;
      grid-template-columns: 1fr auto auto;
      gap: var(--dc-space-2);
      align-items: center;
      padding: var(--dc-space-2) var(--dc-space-3);
      background: var(--dc-surface-1);
      border: 1px solid var(--dc-border);
      border-radius: var(--dc-radius-md);
    }
    input {
      background: var(--dc-bg);
      color: var(--dc-text);
      border: 1px solid var(--dc-border);
      border-radius: var(--dc-radius-sm);
      padding: 6px 10px;
      font-family: var(--dc-font-mono);
      font-size: var(--dc-fs-md);
    }
    input:focus { outline: none; border-color: var(--dc-primary); }

    .stats {
      color: var(--dc-text-muted);
      font-size: var(--dc-fs-xs);
      letter-spacing: 0.06em;
    }

    .body {
      display: grid;
      grid-template-columns: minmax(0, 1fr) 380px;
      gap: var(--dc-space-3);
      min-height: 0;
    }
    .table-wrap, .detail {
      overflow: auto;
      border: 1px solid var(--dc-border);
      border-radius: var(--dc-radius-md);
      background: var(--dc-surface-1);
    }

    table {
      width: 100%;
      border-collapse: collapse;
      font-size: var(--dc-fs-sm);
    }
    thead { position: sticky; top: 0; z-index: 1; }
    th, td {
      text-align: left;
      padding: 6px 10px;
      border-bottom: 1px solid var(--dc-border);
      white-space: nowrap;
    }
    th {
      background: var(--dc-surface-2);
      color: var(--dc-text-faint);
      font-weight: 700;
      letter-spacing: 0.10em;
      text-transform: uppercase;
      font-size: var(--dc-fs-xs);
    }
    tr.sel td { background: var(--dc-row-selected); }
    tr.row { cursor: pointer; }
    tr.row:hover td { background: var(--dc-row-hover); }
    td.target {
      max-width: 280px;
      overflow: hidden;
      text-overflow: ellipsis;
      color: var(--dc-text);
    }

    .sev {
      display: inline-block;
      padding: 1px 6px;
      border: 1px solid var(--dc-border);
      border-radius: var(--dc-radius-sm);
      font-size: var(--dc-fs-xs);
      letter-spacing: 0.06em;
    }
    .sev.critical { color: var(--dc-critical); border-color: var(--dc-critical); }
    .sev.high     { color: var(--dc-high);     border-color: var(--dc-high); }
    .sev.medium   { color: var(--dc-medium);   border-color: var(--dc-medium); }
    .sev.low      { color: var(--dc-low);      border-color: var(--dc-low); }
    .sev.info     { color: var(--dc-info);     border-color: var(--dc-info); }

    .detail {
      padding: var(--dc-space-3);
      font-family: var(--dc-font-mono);
      font-size: var(--dc-fs-sm);
    }
    .detail h3 {
      margin: 0 0 var(--dc-space-2) 0;
      color: var(--dc-accent);
      letter-spacing: 0.14em;
      text-transform: uppercase;
      font-size: var(--dc-fs-md);
    }
    .detail dl { margin: 0; display: grid; grid-template-columns: 110px 1fr; gap: 4px 8px; }
    .detail dt { color: var(--dc-text-faint); font-size: var(--dc-fs-xs); text-transform: uppercase; letter-spacing: 0.10em; }
    .detail dd { margin: 0; color: var(--dc-text); word-break: break-word; }
    .detail .details-blob {
      margin-top: var(--dc-space-3);
      padding: var(--dc-space-2);
      background: var(--dc-bg);
      border: 1px solid var(--dc-border);
      border-radius: var(--dc-radius-sm);
      white-space: pre-wrap;
      word-break: break-word;
      font-size: var(--dc-fs-xs);
      color: var(--dc-text-muted);
    }

    .empty {
      padding: var(--dc-space-5);
      color: var(--dc-text-muted);
      font-style: italic;
      text-align: center;
    }

    .err {
      padding: var(--dc-space-2) var(--dc-space-3);
      border: 1px solid var(--dc-critical);
      border-radius: var(--dc-radius-sm);
      color: var(--dc-critical);
      font-size: var(--dc-fs-sm);
    }
  `;

  @state() private filterText = "";
  @state() private selectedID: string | null = null;

  private poll = new PollController<AuditResponse>(
    this,
    () => api.get<AuditResponse>("/v1/audit?limit=500"),
    5000,
  );

  private get events(): AuditEvent[] {
    return this.poll.state.value?.events ?? [];
  }

  private get filtered(): AuditEvent[] {
    const terms = parseFilter(this.filterText);
    return applyFilter(this.events, terms);
  }

  private onFilterInput = (e: Event): void => {
    this.filterText = (e.target as HTMLInputElement).value;
  };

  private select(id: string): void {
    this.selectedID = this.selectedID === id ? null : id;
  }

  private get selected(): AuditEvent | null {
    if (!this.selectedID) return null;
    return this.events.find((e) => e.id === this.selectedID) ?? null;
  }

  override render() {
    return html`
      <div class="header">
        <div>
          <h1>// AUDIT</h1>
          <div class="subtitle dc-hint">
            Append-only evidence trail. Compound filter syntax: <code>action=verdict severity>=high actor=remo</code>
          </div>
        </div>
        <div class="stats">
          showing ${this.filtered.length} of ${this.events.length}
          ${this.poll.state.freshness === "stale" ? html` · <span style="color: var(--dc-medium);">stale</span>` : nothing}
        </div>
      </div>

      ${this.poll.state.error ? html`<div class="err">✗ ${this.poll.state.error.message}</div>` : nothing}

      <div class="filter-bar">
        <input
          type="text"
          placeholder="action=verdict severity>=high target_contains=github  (or bare keyword)"
          .value=${this.filterText}
          @input=${this.onFilterInput}
        />
        <button @click=${() => { this.filterText = ""; }}>CLEAR</button>
        <button @click=${() => void this.poll.refresh()}>RELOAD</button>
      </div>

      <div class="body">
        <div class="table-wrap">
          ${this.renderTable()}
        </div>
        <aside class="detail">
          ${this.renderDetail()}
        </aside>
      </div>
    `;
  }

  private renderTable() {
    const rows = this.filtered;
    if (rows.length === 0) {
      return html`<div class="empty">no rows match · clear the filter to widen</div>`;
    }
    return html`
      <table>
        <thead>
          <tr>
            <th>Time</th>
            <th>Severity</th>
            <th>Action</th>
            <th>Target</th>
            <th>Actor</th>
            <th>Run</th>
          </tr>
        </thead>
        <tbody>
          ${rows.map((e) => {
            const sev = (e.severity ?? "INFO").toUpperCase();
            const sevCls = SEV_CLASS[sev] ?? "info";
            const ts = new Date(e.timestamp).toLocaleTimeString();
            return html`
              <tr class="row ${this.selectedID === e.id ? "sel" : ""}" @click=${() => this.select(e.id)}>
                <td>${ts}</td>
                <td><span class="sev ${sevCls}">${sev}</span></td>
                <td>${e.action}</td>
                <td class="target" title=${e.target}>${e.target || "—"}</td>
                <td>${e.actor || "—"}</td>
                <td>${e.run_id ?? "—"}</td>
              </tr>
            `;
          })}
        </tbody>
      </table>
    `;
  }

  private renderDetail() {
    const e = this.selected;
    if (!e) {
      return html`<div class="empty">click a row to inspect</div>`;
    }
    const fields: Array<[string, string]> = [
      ["id", e.id],
      ["timestamp", e.timestamp],
      ["action", e.action],
      ["severity", e.severity ?? "—"],
      ["target", e.target || "—"],
      ["actor", e.actor || "—"],
      ["run_id", e.run_id ?? "—"],
      ["trace_id", e.trace_id ?? "—"],
      ["request_id", e.request_id ?? "—"],
      ["session_id", e.session_id ?? "—"],
      ["agent_name", e.agent_name ?? "—"],
      ["policy_id", e.policy_id ?? "—"],
      ["destination_app", e.destination_app ?? "—"],
      ["tool_name", e.tool_name ?? "—"],
    ];
    return html`
      <h3>EVIDENCE</h3>
      <dl>
        ${fields.map(([k, v]) => html`<dt>${k}</dt><dd>${v}</dd>`)}
      </dl>
      ${e.details ? html`<div class="details-blob">${e.details}</div>` : nothing}
    `;
  }
}

declare global {
  interface HTMLElementTagNameMap { "dc-audit": DcAudit; }
}
