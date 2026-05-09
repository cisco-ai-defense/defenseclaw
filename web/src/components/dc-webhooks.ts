import { LitElement, html, css, nothing } from "lit";
import { customElement, state } from "lit/decorators.js";
import { api, type ApiError } from "../lib/api";

interface Webhook {
  name?: string;
  url: string;
  type: string;
  secret_env?: string;
  room_id?: string;
  min_severity?: string;
  events?: string[];
  timeout_seconds?: number;
  cooldown_seconds?: number;
  enabled: boolean;
}

interface WebhooksResponse { webhooks: Webhook[] | null; }
interface ActionResponse {
  ok: boolean;
  exit_code: number;
  argv: string[];
  output: string;
}

const ACTIONS = ["enable", "disable", "remove", "test"] as const;
type Action = typeof ACTIONS[number];

/**
 * Webhooks list + admin actions. Mirrors the TUI's webhooks editor
 * (internal/tui/setup_webhooks.go). Same shape as dc-sinks, swapping the
 * API path and column set.
 */
@customElement("dc-webhooks")
export class DcWebhooks extends LitElement {
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
    td.url {
      max-width: 360px;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      color: var(--dc-text-muted);
    }
    td.events {
      color: var(--dc-text-muted);
      font-size: var(--dc-fs-xs);
    }

    .name  { font-weight: 700; color: var(--dc-text-bright); }
    .type  { color: var(--dc-accent); text-transform: uppercase; letter-spacing: 0.06em; }
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

  @state() private hooks: Webhook[] = [];
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
      const res = await api.get<WebhooksResponse>("/v1/webhooks");
      this.hooks = res.webhooks ?? [];
    } catch (err) {
      const e = err as ApiError;
      this.err = e.status ? `HTTP ${e.status}` : `failed: ${e.message}`;
    }
  }

  private async runAction(name: string, action: Action): Promise<void> {
    if (action === "remove" && !confirm(`Remove webhook "${name}"?`)) return;
    this.busyName = `${name}:${action}`;
    this.lastResult = null;
    try {
      const res = await api.post<ActionResponse>(`/v1/webhooks/${encodeURIComponent(name)}/${action}`);
      this.lastResult = { name, action, res };
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
          <div class="dc-section">WEBHOOKS</div>
          <div class="dc-hint" style="font-size: var(--dc-fs-xs);">
            Slack / PagerDuty / Webex / generic dispatchers. Add new with the WEBHOOK wizard.
          </div>
        </div>
        <button @click=${() => void this.load()}>RELOAD</button>
      </div>

      ${this.err ? html`<div class="banner err">✗ ${this.err}</div>` : nothing}
      ${this.renderResult()}

      ${this.hooks.length === 0
        ? html`<div class="empty">no webhooks configured · run the WEBHOOK wizard to add one</div>`
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
            <th>Type</th>
            <th>URL</th>
            <th>Min severity</th>
            <th>Events</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          ${this.hooks.map((h) => this.renderRow(h))}
        </tbody>
      </table>
    `;
  }

  private renderRow(h: Webhook) {
    const name = h.name ?? "(unnamed)";
    const sev = (h.min_severity ?? "info").toLowerCase();
    const events = h.events && h.events.length > 0 ? h.events.join(", ") : "—";
    return html`
      <tr>
        <td>
          <span class="dot" style="color: ${h.enabled ? "var(--dc-clean)" : "var(--dc-text-faint)"};">
            ${h.enabled ? "●" : "○"}
          </span>
        </td>
        <td><span class="name">${name}</span></td>
        <td><span class="type">${h.type}</span></td>
        <td class="url" title=${h.url}>${h.url}</td>
        <td><span class="sev ${sev}">${(h.min_severity ?? "info").toUpperCase()}</span></td>
        <td class="events">${events}</td>
        <td class="actions">
          ${ACTIONS.map((a) => {
            const busy = this.busyName === `${name}:${a}`;
            const disabled = !!this.busyName;
            const danger = a === "remove";
            return html`
              <button
                class="action ${danger ? "danger" : ""}"
                ?disabled=${disabled}
                @click=${() => void this.runAction(name, a)}
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
  interface HTMLElementTagNameMap { "dc-webhooks": DcWebhooks; }
}
