import { LitElement, html, css, nothing } from "lit";
import { customElement, state } from "lit/decorators.js";
import { api, type ApiError } from "../lib/api";

interface WizardSpec {
  name: string;
  argv_prefix: string[];
  require_positional: boolean;
  allowed_positional?: string[];
}

interface WizardListResponse {
  wizards: WizardSpec[];
}

type StreamEvent =
  | { event: "start"; argv: string[] }
  | { event: "stdout"; line: string }
  | { event: "stderr"; line: string }
  | { event: "cancelled" }
  | { event: "exit"; code: number; error?: string };

type RunStatus =
  | { kind: "idle" }
  | { kind: "running" }
  | { kind: "done"; code: number }
  | { kind: "cancelled" };

interface FlagPair { key: string; value: string; }

/**
 * Setup wizards — runs the same eight CLI flows the TUI's Setup panel uses
 * (skill-scanner, mcp-scanner, gateway, guardrail, splunk, observability,
 * webhook, sandbox). Server-side allowlists the wizard name + positional;
 * flag keys must match [a-z][a-z0-9-]*. The output streams as NDJSON.
 *
 * v1 surfaces a generic flag editor — typed per-wizard forms come later
 * once we have the field catalog from the CLI's --json help output.
 */
@customElement("dc-setup-wizards")
export class DcSetupWizards extends LitElement {
  static override styles = css`
    :host { display: grid; gap: var(--dc-space-4); }

    .cards {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
      gap: var(--dc-space-2);
    }
    .card {
      padding: var(--dc-space-3);
      border: 1px solid var(--dc-border);
      border-radius: var(--dc-radius-md);
      background: var(--dc-surface-1);
      cursor: pointer;
      text-align: left;
      letter-spacing: 0.10em;
      font-family: var(--dc-font-mono);
      color: var(--dc-text);
      transition: border-color 0.08s linear;
    }
    .card:hover { border-color: var(--dc-primary); }
    .card.selected {
      border-color: var(--dc-accent);
      background: var(--dc-surface-2);
    }
    .card-name { font-size: var(--dc-fs-md); color: var(--dc-text-bright); }
    .card-sub  { font-size: var(--dc-fs-xs); color: var(--dc-text-faint); margin-top: 2px; }

    .form {
      display: grid;
      gap: var(--dc-space-2);
      padding: var(--dc-space-3);
      border: 1px solid var(--dc-primary);
      border-radius: var(--dc-radius-md);
      background: var(--dc-surface-1);
    }
    .form-row {
      display: grid;
      grid-template-columns: 160px 1fr auto;
      gap: var(--dc-space-2);
      align-items: center;
    }
    label {
      color: var(--dc-text-muted);
      font-size: var(--dc-fs-xs);
      letter-spacing: 0.10em;
      text-transform: uppercase;
    }
    input, select {
      background: var(--dc-bg);
      color: var(--dc-text);
      border: 1px solid var(--dc-border);
      border-radius: var(--dc-radius-sm);
      padding: 6px 10px;
      font-family: var(--dc-font-mono);
      font-size: var(--dc-fs-md);
      min-width: 0;
    }
    input:focus, select:focus { outline: none; border-color: var(--dc-primary); }

    .flags-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding-top: var(--dc-space-2);
      border-top: 1px dashed var(--dc-border);
    }
    .form-actions {
      display: flex;
      gap: var(--dc-space-2);
      justify-content: flex-end;
      padding-top: var(--dc-space-2);
      border-top: 1px solid var(--dc-border);
    }

    pre {
      margin: 0;
      padding: var(--dc-space-3);
      background: var(--dc-bg);
      border: 1px solid var(--dc-border);
      border-radius: var(--dc-radius-md);
      font-family: var(--dc-font-mono);
      font-size: var(--dc-fs-sm);
      color: var(--dc-text);
      white-space: pre-wrap;
      word-break: break-word;
      max-height: 400px;
      overflow-y: auto;
    }
    .stream-stdout { color: var(--dc-text); }
    .stream-stderr { color: var(--dc-medium); }
    .stream-meta   { color: var(--dc-text-faint); font-style: italic; }
    .stream-exit-ok   { color: var(--dc-clean); font-weight: 700; }
    .stream-exit-fail { color: var(--dc-critical); font-weight: 700; }
    .stream-cancelled { color: var(--dc-quarantine); font-weight: 700; }

    button.action.danger { color: var(--dc-critical); }
    button.action.danger:hover { border-color: var(--dc-critical); }

    .empty {
      padding: var(--dc-space-4);
      border: 1px dashed var(--dc-border);
      border-radius: var(--dc-radius-md);
      color: var(--dc-text-muted);
      font-style: italic;
      text-align: center;
    }
  `;

  @state() private wizards: WizardSpec[] = [];
  @state() private loadError = "";
  @state() private selected: WizardSpec | null = null;
  @state() private positional = "";
  @state() private flags: FlagPair[] = [];
  @state() private status: RunStatus = { kind: "idle" };
  @state() private events: StreamEvent[] = [];

  // AbortController for the in-flight wizard fetch. The server cancels the
  // child process when its request context is cancelled (exec.CommandContext),
  // so aborting the fetch on the client side propagates all the way through
  // to the CLI subprocess.
  private abortController: AbortController | null = null;

  override disconnectedCallback(): void {
    super.disconnectedCallback();
    this.cancel();
  }

  private cancel = (): void => {
    if (this.abortController) {
      this.abortController.abort();
      this.abortController = null;
    }
  };

  override connectedCallback(): void {
    super.connectedCallback();
    void this.loadWizards();
  }

  private async loadWizards(): Promise<void> {
    try {
      const res = await api.get<WizardListResponse>("/v1/setup/wizards");
      this.wizards = res.wizards;
    } catch (err) {
      const e = err as ApiError;
      this.loadError = e.status
        ? `GET /v1/setup/wizards → HTTP ${e.status}`
        : `failed: ${e.message}`;
    }
  }

  private select(w: WizardSpec): void {
    this.selected = w;
    this.positional = w.allowed_positional?.[0] ?? "";
    this.flags = [{ key: "", value: "" }];
    this.events = [];
    this.status = { kind: "idle" };
  }

  private addFlag(): void {
    this.flags = [...this.flags, { key: "", value: "" }];
  }

  private removeFlag(i: number): void {
    this.flags = this.flags.filter((_, idx) => idx !== i);
  }

  private updateFlag(i: number, key: keyof FlagPair, value: string): void {
    this.flags = this.flags.map((f, idx) => (idx === i ? { ...f, [key]: value } : f));
  }

  private async run(): Promise<void> {
    if (!this.selected) return;
    this.status = { kind: "running" };
    this.events = [];
    this.abortController = new AbortController();

    const flagsObj: Record<string, string> = {};
    for (const f of this.flags) {
      const k = f.key.trim();
      if (!k) continue;
      flagsObj[k] = f.value;
    }

    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      "X-DefenseClaw-Client": "dc-web/0.1",
      Accept: "application/x-ndjson",
    };
    const token = localStorage.getItem("dc.token");
    if (token) headers["Authorization"] = `Bearer ${token}`;

    let res: Response;
    try {
      res = await fetch("/v1/setup/run", {
        method: "POST",
        headers,
        signal: this.abortController.signal,
        body: JSON.stringify({
          wizard: this.selected.name,
          positional: this.positional || undefined,
          flags: flagsObj,
        }),
      });
    } catch (err) {
      // AbortError surfaces here when the user clicks STOP before headers
      // arrive. Distinguish it from real network errors so the banner can
      // say "cancelled" instead of "exit -1".
      if ((err as Error).name === "AbortError") {
        this.appendEvent({ event: "cancelled" });
        this.status = { kind: "cancelled" };
        return;
      }
      this.appendEvent({ event: "stderr", line: `network error: ${(err as Error).message}` });
      this.status = { kind: "done", code: -1 };
      return;
    }

    if (!res.ok || !res.body) {
      const text = await res.text();
      this.appendEvent({ event: "stderr", line: `HTTP ${res.status}: ${text}` });
      this.status = { kind: "done", code: res.status };
      return;
    }

    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buf = "";
    let exitCode = 0;
    let cancelled = false;
    try {
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });
        const lines = buf.split("\n");
        buf = lines.pop() ?? "";
        for (const line of lines) {
          if (!line.trim()) continue;
          try {
            const evt = JSON.parse(line) as StreamEvent;
            this.appendEvent(evt);
            if (evt.event === "exit")      exitCode = evt.code;
            if (evt.event === "cancelled") cancelled = true;
          } catch {
            this.appendEvent({ event: "stderr", line: `parse error: ${line}` });
          }
        }
      }
    } catch (err) {
      // Stream interrupted mid-flight by an abort. Server context will
      // have cancelled the child process; surface the same "cancelled"
      // state so the user knows it landed cleanly.
      if ((err as Error).name === "AbortError") {
        this.appendEvent({ event: "cancelled" });
        this.status = { kind: "cancelled" };
        this.abortController = null;
        return;
      }
      throw err;
    }
    this.abortController = null;
    this.status = cancelled ? { kind: "cancelled" } : { kind: "done", code: exitCode };
  }

  private appendEvent(evt: StreamEvent): void {
    this.events = [...this.events, evt];
  }

  override render() {
    if (this.loadError) {
      return html`<div class="empty">${this.loadError}</div>`;
    }
    if (this.wizards.length === 0) {
      return html`<div class="empty">loading wizards…</div>`;
    }
    return html`
      <div>
        <div class="dc-section" style="margin-bottom: var(--dc-space-2);">PICK A WIZARD</div>
        <div class="cards">
          ${this.wizards.map((w) => html`
            <button
              class="card ${this.selected?.name === w.name ? "selected" : ""}"
              @click=${() => this.select(w)}
            >
              <div class="card-name">${w.name.toUpperCase().replace(/-/g, " ")}</div>
              <div class="card-sub">defenseclaw ${w.argv_prefix.join(" ")}</div>
            </button>
          `)}
        </div>
      </div>

      ${this.selected ? this.renderForm(this.selected) : nothing}
      ${this.events.length > 0 ? this.renderOutput() : nothing}
    `;
  }

  private renderForm(w: WizardSpec) {
    const running = this.status.kind === "running";
    return html`
      <form class="form" @submit=${(e: Event) => { e.preventDefault(); void this.run(); }}>
        <div class="form-row">
          <label>WIZARD</label>
          <code>${w.argv_prefix.join(" ")} ${w.require_positional ? "&lt;positional&gt;" : ""} --non-interactive</code>
          <span></span>
        </div>

        ${w.require_positional ? html`
          <div class="form-row">
            <label>POSITIONAL</label>
            ${w.allowed_positional && w.allowed_positional.length > 0 ? html`
              <select
                .value=${this.positional}
                @change=${(e: Event) => { this.positional = (e.target as HTMLSelectElement).value; }}
                ?disabled=${running}
              >
                ${w.allowed_positional.map((p) => html`<option value=${p} ?selected=${p === this.positional}>${p}</option>`)}
              </select>
            ` : html`
              <input
                type="text"
                .value=${this.positional}
                @input=${(e: Event) => { this.positional = (e.target as HTMLInputElement).value; }}
                ?disabled=${running}
                placeholder="required"
              />
            `}
            <span></span>
          </div>
        ` : nothing}

        <div class="flags-header">
          <span class="dc-section">FLAGS</span>
          <button type="button" @click=${() => this.addFlag()} ?disabled=${running}>+ ADD</button>
        </div>

        ${this.flags.map((f, i) => html`
          <div class="form-row">
            <input
              type="text"
              placeholder="flag-name (e.g. realm)"
              .value=${f.key}
              @input=${(e: Event) => this.updateFlag(i, "key", (e.target as HTMLInputElement).value)}
              ?disabled=${running}
            />
            <input
              type="text"
              placeholder="value"
              .value=${f.value}
              @input=${(e: Event) => this.updateFlag(i, "value", (e.target as HTMLInputElement).value)}
              ?disabled=${running}
            />
            <button type="button" @click=${() => this.removeFlag(i)} ?disabled=${running}>×</button>
          </div>
        `)}

        <div class="form-actions">
          ${running ? html`
            <button type="button" class="action danger" @click=${this.cancel}>STOP</button>
          ` : nothing}
          <button type="submit" ?disabled=${running}>
            ${running ? "RUNNING…" : "RUN"}
          </button>
        </div>
      </form>
    `;
  }

  private renderOutput() {
    return html`
      <div>
        <div class="dc-section" style="margin-bottom: var(--dc-space-2);">OUTPUT</div>
        <pre>${this.events.map((e) => this.renderEvent(e))}</pre>
      </div>
    `;
  }

  private renderEvent(e: StreamEvent) {
    if (e.event === "start") {
      return html`<span class="stream-meta">$ ${e.argv.join(" ")}</span>\n`;
    }
    if (e.event === "stdout") {
      return html`<span class="stream-stdout">${e.line}</span>\n`;
    }
    if (e.event === "stderr") {
      return html`<span class="stream-stderr">${e.line}</span>\n`;
    }
    if (e.event === "exit") {
      const cls = e.code === 0 ? "stream-exit-ok" : "stream-exit-fail";
      return html`<span class=${cls}>--- exit ${e.code} ---</span>\n`;
    }
    if (e.event === "cancelled") {
      return html`<span class="stream-cancelled">--- cancelled by operator ---</span>\n`;
    }
    return nothing;
  }
}

declare global {
  interface HTMLElementTagNameMap { "dc-setup-wizards": DcSetupWizards; }
}
