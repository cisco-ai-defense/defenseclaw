import { LitElement, html, css, nothing } from "lit";
import { customElement, state } from "lit/decorators.js";
import { api } from "../lib/api";
import { PollController } from "../lib/poll";

interface LogsResponse {
  path: string;
  size: number;
  lines: string[];
  note?: string;
}

@customElement("dc-logs")
export class DcLogs extends LitElement {
  static override styles = css`
    :host { display: grid; grid-template-rows: auto auto minmax(0, 1fr); gap: var(--dc-space-3); height: 100%; min-height: 0; }

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

    .toolbar {
      display: grid;
      grid-template-columns: 1fr auto auto auto;
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
    .meta {
      color: var(--dc-text-muted);
      font-size: var(--dc-fs-xs);
      letter-spacing: 0.06em;
    }

    .pane {
      overflow: auto;
      background: var(--dc-bg);
      border: 1px solid var(--dc-border);
      border-radius: var(--dc-radius-md);
    }
    .pane pre {
      margin: 0;
      padding: var(--dc-space-3);
      font-family: var(--dc-font-mono);
      font-size: var(--dc-fs-xs);
      color: var(--dc-text);
      white-space: pre;
    }

    .line { display: block; }
    .line.match { background: rgba(95, 95, 215, 0.18); }
    .line.error { color: var(--dc-critical); }
    .line.warn  { color: var(--dc-medium); }

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
  @state() private follow = true;
  @state() private autoScrollDirty = false;

  private poll = new PollController<LogsResponse>(
    this,
    () => api.get<LogsResponse>("/v1/logs?tail=500"),
    2000,
  );

  override updated(): void {
    if (this.follow && !this.autoScrollDirty) {
      const pane = this.renderRoot?.querySelector(".pane");
      if (pane) pane.scrollTop = pane.scrollHeight;
    }
  }

  private onScroll = (e: Event): void => {
    const el = e.target as HTMLElement;
    const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 20;
    this.autoScrollDirty = !atBottom;
  };

  override render() {
    const v = this.poll.state.value;
    const err = this.poll.state.error;
    return html`
      <div class="header">
        <div>
          <h1>// LOGS</h1>
          <div class="subtitle dc-hint">Tail of ${v?.path ?? "~/.defenseclaw/gateway.log"}</div>
        </div>
        <div class="meta">
          ${v ? `${v.lines.length} lines · ${formatBytes(v.size)}` : "loading…"}
          ${this.poll.state.freshness === "stale" ? html` · <span style="color: var(--dc-medium);">stale</span>` : nothing}
        </div>
      </div>

      ${err ? html`<div class="err">✗ ${err.message}</div>` : nothing}

      <div class="toolbar">
        <input
          type="text"
          placeholder="filter (substring)…"
          .value=${this.filterText}
          @input=${(e: Event) => { this.filterText = (e.target as HTMLInputElement).value; }}
        />
        <label class="meta" style="display: inline-flex; align-items: center; gap: 4px;">
          <input
            type="checkbox"
            .checked=${this.follow}
            @change=${(e: Event) => { this.follow = (e.target as HTMLInputElement).checked; }}
            style="width: auto; padding: 0;"
          />
          FOLLOW
        </label>
        <button @click=${() => { this.filterText = ""; }}>CLEAR</button>
        <button @click=${() => void this.poll.refresh()}>RELOAD</button>
      </div>

      <div class="pane" @scroll=${this.onScroll}>
        ${this.renderLines(v?.lines ?? [])}
      </div>
    `;
  }

  private renderLines(lines: string[]) {
    if (lines.length === 0) {
      return html`<div class="empty">no log lines yet</div>`;
    }
    const q = this.filterText.trim().toLowerCase();
    return html`
      <pre>${lines.map((line) => {
        const lower = line.toLowerCase();
        if (q && !lower.includes(q)) return nothing;
        let cls = "line";
        if (lower.includes("error") || lower.includes("[err]")) cls += " error";
        else if (lower.includes("warn"))                         cls += " warn";
        if (q && lower.includes(q))                              cls += " match";
        return html`<span class=${cls}>${line}\n</span>`;
      })}</pre>
    `;
  }
}

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MB`;
  return `${(n / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

declare global {
  interface HTMLElementTagNameMap { "dc-logs": DcLogs; }
}
