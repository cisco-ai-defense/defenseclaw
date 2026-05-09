import { LitElement, html, css, nothing } from "lit";
import { customElement, state } from "lit/decorators.js";
import { api, type ApiError } from "../lib/api";

interface Sink {
  name: string;
  kind: string;
  enabled: boolean;
  min_severity?: string;
  actions?: string[];
  batch_size?: number;
  flush_interval_s?: number;
  timeout_s?: number;
  splunk_hec?: Record<string, unknown>;
  otlp_logs?: Record<string, unknown>;
  http_jsonl?: Record<string, unknown>;
}

interface SinksResponse { sinks: Sink[] | null; }
interface ActionResponse {
  ok: boolean;
  exit_code: number;
  argv: string[];
  output: string;
}

const ACTIONS = ["enable", "disable", "remove", "test"] as const;
type Action = typeof ACTIONS[number];

/**
 * Audit sinks list + admin actions. Mirrors the TUI's audit-sinks editor
 * (internal/tui/setup_sinks.go). Reads come from /v1/sinks; mutations
 * shell `defenseclaw setup observability {action} <name>` server-side and
 * return synchronous {ok, exit_code, output}.
 */
@customElement("dc-sinks")
export class DcSinks extends LitElement {
  static override styles = css`
    :host { display: grid; gap: var(--dc-space-3); }

    table {
      width: 100%;
      border-collapse: collapse;
      font-size: var(--dc-fs-sm);
      background: var(--dc-surface-1);
      border: 1px solid var(--dc-border);
      border-radius: var(--dc-radius-md);
      overflow: hidden;
    }
    th, td {
      text-align: left;
      padding: 8px 12px;
      border-bottom: 1px solid var(--dc-border);
      vertical-align: middle;
    }
    th {
      background: var(--dc-surface-2);
      color: var(--dc-text-faint);
      font-weight: 700;
      letter-spacing: 0.10em;
      text-transform: uppercase;
      font-size: var(--dc-fs-xs);
    }
    tr:last-child td { border-bottom: none; }
    td.actions { text-align: right; white-space: nowrap; }

    .name  { font-weight: 700; color: var(--dc-text-bright); }
    .kind  { color: var(--dc-accent); }
    .dot   { display: inline-block; width: 8px; }
    .sev   {
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

    button.action {
      padding: 3px 9px;
      font-size: var(--dc-fs-xs);
      letter-spacing: 0.10em;
      margin-left: 4px;
    }
    button.action.danger { color: var(--dc-critical); }
    button.action.danger:hover { border-color: var(--dc-critical); }
    button.action:disabled { opacity: 0.4; cursor: not-allowed; }

    .empty {
      padding: var(--dc-space-4);
      border: 1px dashed var(--dc-border);
      border-radius: var(--dc-radius-md);
      color: var(--dc-text-muted);
      font-style: italic;
      text-align: center;
    }

    .banner {
      padding: var(--dc-space-2) var(--dc-space-3);
      border: 1px solid var(--dc-border);
      border-radius: var(--dc-radius-sm);
      font-size: var(--dc-fs-sm);
    }
    .banner.ok  { border-color: var(--dc-clean);    color: var(--dc-clean); }
    .banner.err { border-color: var(--dc-critical); color: var(--dc-critical); }

    pre.output {
      margin: 4px 0 0 0;
      padding: 8px 10px;
      background: var(--dc-bg);
      border: 1px solid var(--dc-border);
      border-radius: var(--dc-radius-sm);
      font-family: var(--dc-font-mono);
      font-size: var(--dc-fs-xs);
      color: var(--dc-text-muted);
      white-space: pre-wrap;
      word-break: break-word;
      max-height: 200px;
      overflow-y: auto;
    }

    .header {
      display: flex;
      align-items: baseline;
      justify-content: space-between;
      gap: var(--dc-space-3);
    }
  `;

  @state() private sinks: Sink[] = [];
  @state() private err = "";
  @state() private busyName = "";
  @state() private lastResult: { name: string; action: Action; res: ActionResponse | { error: string } } | null = null;

  override connectedCallback(): void {
    super.connectedCallback();
    void this.load();
  }

  private async load(): Promise<void> {
    this.err = "";
    try {
      const res = await api.get<SinksResponse>("/v1/sinks");
      this.sinks = res.sinks ?? [];
    } catch (err) {
      const e = err as ApiError;
      this.err = e.status ? `HTTP ${e.status}` : `failed: ${e.message}`;
    }
  }

  private async runAction(name: string, action: Action): Promise<void> {
    if (action === "remove" && !confirm(`Remove sink "${name}"?`)) return;
    this.busyName = `${name}:${action}`;
    this.lastResult = null;
    try {
      const res = await api.post<ActionResponse>(`/v1/sinks/${encodeURIComponent(name)}/${action}`);
      this.lastResult = { name, action, res };
      // Reload list state so toggled enabled flags / removed entries reflect.
      await this.load();
    } catch (err) {
      const e = err as ApiError;
      this.lastResult = {
        name, action,
        res: { error: e.status ? `HTTP ${e.status}: ${this.bodyMsg(e.body)}` : e.message },
      };
    } finally {
      this.busyName = "";
    }
  }

  private bodyMsg(body: unknown): string {
    if (!body) return "";
    if (typeof body === "string") return body;
    if (typeof body === "object" && body && "error" in body) {
      return String((body as { error: unknown }).error);
    }
    return JSON.stringify(body);
  }

  override render() {
    return html`
      <div class="header">
        <div>
          <div class="dc-section">AUDIT SINKS</div>
          <div class="dc-hint" style="font-size: var(--dc-fs-xs);">
            Configured exporters (splunk_hec / otlp_logs / http_jsonl). Add new with the OBSERVABILITY wizard.
          </div>
        </div>
        <button @click=${() => void this.load()}>RELOAD</button>
      </div>

      ${this.err ? html`<div class="banner err">✗ ${this.err}</div>` : nothing}
      ${this.renderResult()}

      ${this.sinks.length === 0
        ? html`<div class="empty">no sinks configured · run the OBSERVABILITY wizard to add one</div>`
        : this.renderTable()}
    `;
  }

  private renderTable() {
    return html`
      <table>
        <thead>
          <tr>
            <th></th>
            <th>Name</th>
            <th>Kind</th>
            <th>Min severity</th>
            <th>Batch / flush / timeout</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          ${this.sinks.map((s) => this.renderRow(s))}
        </tbody>
      </table>
    `;
  }

  private renderRow(s: Sink) {
    const sev = (s.min_severity ?? "info").toLowerCase();
    return html`
      <tr>
        <td>
          <span class="dot" style="color: ${s.enabled ? "var(--dc-clean)" : "var(--dc-text-faint)"};">
            ${s.enabled ? "●" : "○"}
          </span>
        </td>
        <td><span class="name">${s.name}</span></td>
        <td><span class="kind">${s.kind}</span></td>
        <td><span class="sev ${sev}">${(s.min_severity ?? "info").toUpperCase()}</span></td>
        <td>
          ${s.batch_size ?? "—"} · ${s.flush_interval_s ?? "—"}s · ${s.timeout_s ?? "—"}s
        </td>
        <td class="actions">
          ${ACTIONS.map((a) => {
            const busy = this.busyName === `${s.name}:${a}`;
            const disabled = !!this.busyName;
            const danger = a === "remove";
            return html`
              <button
                class="action ${danger ? "danger" : ""}"
                ?disabled=${disabled}
                @click=${() => void this.runAction(s.name, a)}
                title=${a}
              >${busy ? "…" : a.toUpperCase()}</button>
            `;
          })}
        </td>
      </tr>
    `;
  }

  private renderResult() {
    if (!this.lastResult) return nothing;
    const { name, action, res } = this.lastResult;
    if ("error" in res) {
      return html`<div class="banner err">✗ ${name} · ${action} → ${res.error}</div>`;
    }
    const ok = res.ok;
    return html`
      <div class="banner ${ok ? "ok" : "err"}">
        ${ok ? "✓" : "✗"} ${name} · ${action} → exit ${res.exit_code}
        ${res.output ? html`<pre class="output">${res.output}</pre>` : nothing}
      </div>
    `;
  }
}

declare global {
  interface HTMLElementTagNameMap { "dc-sinks": DcSinks; }
}
