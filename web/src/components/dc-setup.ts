import { LitElement, html, css, nothing } from "lit";
import { customElement, state } from "lit/decorators.js";
import { api, setToken, type ApiError } from "../lib/api";
import "./dc-setup-wizards";
import "./dc-sinks";
import "./dc-webhooks";

type Tab = "wizards" | "sinks" | "webhooks" | "config";

interface ConfigResponse {
  config: Record<string, unknown>;
  yaml: string;
  path: string;
}

interface SaveResponse {
  status: string;
  path: string;
  backup: string;
  needs_restart: string[];
}

type Status =
  | { kind: "idle" }
  | { kind: "loading" }
  | { kind: "loaded"; loadedAt: number }
  | { kind: "saving" }
  | { kind: "saved"; res: SaveResponse; at: number }
  | { kind: "error"; message: string };

/**
 * Setup view, v1 — full-config YAML editor.
 *
 * The TUI's Setup wizards each shell to `defenseclaw setup <flow>` subprocesses,
 * which the browser cannot do. Until the wizard runner endpoint lands
 * (Phase 3), this view exposes the underlying primitive: GET/PUT /v1/config,
 * which is everything the wizards eventually mutate. Operators with YAML
 * fluency can configure the entire stack here today.
 *
 * Subsequent phases will layer typed forms (Wizards, Sinks, Webhooks, MCPs)
 * on top of this same endpoint.
 */
@customElement("dc-setup")
export class DcSetup extends LitElement {
  static override styles = css`
    :host { display: grid; gap: var(--dc-space-4); height: 100%; min-height: 0; }

    .tabs {
      display: flex;
      gap: 0;
      border-bottom: 1px solid var(--dc-border);
    }
    .tab {
      padding: 8px 16px;
      background: transparent;
      border: none;
      border-bottom: 2px solid transparent;
      color: var(--dc-text-muted);
      font-family: var(--dc-font-mono);
      font-size: var(--dc-fs-sm);
      letter-spacing: 0.14em;
      cursor: pointer;
    }
    .tab:hover { color: var(--dc-text); }
    .tab.active {
      color: var(--dc-accent);
      border-bottom-color: var(--dc-accent);
    }

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
    .subtitle {
      color: var(--dc-text-faint);
      font-size: var(--dc-fs-sm);
      letter-spacing: 0.06em;
    }

    .toolbar {
      display: flex;
      gap: var(--dc-space-2);
      align-items: center;
    }
    .toolbar .meta {
      color: var(--dc-text-muted);
      font-size: var(--dc-fs-xs);
      letter-spacing: 0.06em;
    }

    .editor {
      display: grid;
      grid-template-rows: minmax(0, 1fr);
      min-height: 0;
    }
    textarea {
      width: 100%;
      height: 100%;
      min-height: 480px;
      resize: none;
      background: var(--dc-bg);
      color: var(--dc-text);
      border: 1px solid var(--dc-border);
      border-radius: var(--dc-radius-md);
      padding: var(--dc-space-3);
      font-family: var(--dc-font-mono);
      font-size: var(--dc-fs-md);
      line-height: 1.55;
      tab-size: 2;
    }
    textarea:focus {
      outline: none;
      border-color: var(--dc-primary);
    }

    .banner {
      padding: var(--dc-space-2) var(--dc-space-3);
      border: 1px solid var(--dc-border);
      border-radius: var(--dc-radius-sm);
      font-size: var(--dc-fs-sm);
    }
    .banner.ok       { border-color: var(--dc-clean);    color: var(--dc-clean); }
    .banner.warn     { border-color: var(--dc-medium);   color: var(--dc-medium); }
    .banner.err      { border-color: var(--dc-critical); color: var(--dc-critical); }

    .needs-restart {
      margin-top: var(--dc-space-1);
      color: var(--dc-medium);
      font-size: var(--dc-fs-xs);
    }
    .needs-restart ul { margin: 4px 0 0 18px; padding: 0; }

    .dirty-pip {
      color: var(--dc-medium);
      font-style: italic;
    }
  `;

  @state() private status: Status = { kind: "idle" };
  @state() private text = "";
  @state() private originalText = "";
  @state() private path = "";
  @state() private tab: Tab = "wizards";

  override connectedCallback(): void {
    super.connectedCallback();
    if (this.tab === "config") void this.load();
  }

  private switchTab(t: Tab): void {
    this.tab = t;
    if (t === "config" && this.text === "") void this.load();
  }

  private async load(): Promise<void> {
    this.status = { kind: "loading" };
    try {
      const res = await api.get<ConfigResponse>("/v1/config");
      this.text = res.yaml;
      this.originalText = res.yaml;
      this.path = res.path;
      this.status = { kind: "loaded", loadedAt: Date.now() };
    } catch (err) {
      const e = err as ApiError;
      this.status = {
        kind: "error",
        message: e.status
          ? `GET /v1/config → HTTP ${e.status}: ${this.bodyMessage(e.body)}`
          : `GET /v1/config failed: ${e.message}`,
      };
    }
  }

  private async save(): Promise<void> {
    this.status = { kind: "saving" };
    try {
      // Send raw YAML so we don't lose ordering / type fidelity through a
      // JSON round-trip. The gateway re-parses to validate.
      const res = await this.putYaml(this.text);
      this.originalText = this.text;
      this.status = { kind: "saved", res, at: Date.now() };
    } catch (err) {
      const e = err as ApiError;
      this.status = {
        kind: "error",
        message: e.status
          ? `PUT /v1/config → HTTP ${e.status}: ${this.bodyMessage(e.body)}`
          : `PUT /v1/config failed: ${e.message}`,
      };
    }
  }

  private async putYaml(yaml: string): Promise<SaveResponse> {
    // CSRF middleware requires Content-Type: application/json + X-DefenseClaw-Client
    // on every mutation. We wrap the raw YAML text in a JSON envelope so the
    // server preserves it verbatim (no map round-trip that would lose ordering
    // or comments).
    return api.put<SaveResponse>("/v1/config", { yaml });
  }

  private bodyMessage(body: unknown): string {
    if (!body) return "(no body)";
    if (typeof body === "string") return body;
    if (typeof body === "object" && body && "error" in body) {
      return String((body as { error: unknown }).error);
    }
    return JSON.stringify(body);
  }

  private get dirty(): boolean { return this.text !== this.originalText; }

  private onInput = (e: Event): void => {
    this.text = (e.target as HTMLTextAreaElement).value;
  };

  private revert = (): void => {
    this.text = this.originalText;
  };

  private renderTokenPrompt() {
    return html`
      <div class="banner warn">
        <div>The gateway has token auth enabled. Paste $DEFENSECLAW_GATEWAY_TOKEN below; it'll be stored in localStorage.</div>
        <form
          style="display: flex; gap: var(--dc-space-2); margin-top: var(--dc-space-2);"
          @submit=${this.onTokenSubmit}
        >
          <input
            type="password"
            name="token"
            placeholder="bearer token"
            autocomplete="off"
            spellcheck="false"
            style="flex: 1; min-width: 0; background: var(--dc-bg); color: var(--dc-text); border: 1px solid var(--dc-border); border-radius: var(--dc-radius-sm); padding: 6px 10px; font-family: var(--dc-font-mono); font-size: var(--dc-fs-md);"
          />
          <button type="submit">SAVE TOKEN</button>
        </form>
      </div>
    `;
  }

  private onTokenSubmit = (e: Event): void => {
    e.preventDefault();
    const form = e.target as HTMLFormElement;
    const input = form.elements.namedItem("token") as HTMLInputElement | null;
    const v = input?.value.trim() ?? "";
    if (!v) return;
    setToken(v);
    void this.load();
  };

  private renderRevertBtn() {
    if (!this.dirty) return nothing;
    return html`<button @click=${this.revert} title="Discard local edits">REVERT</button>`;
  }

  override render() {
    return html`
      <div>
        <h1>// SETUP</h1>
        <div class="subtitle dc-hint">
          Run setup wizards or edit ~/.defenseclaw/config.yaml directly. Both write the same file.
        </div>
      </div>

      <div class="tabs">
        <button class="tab ${this.tab === "wizards"  ? "active" : ""}" @click=${() => this.switchTab("wizards")}>WIZARDS</button>
        <button class="tab ${this.tab === "sinks"    ? "active" : ""}" @click=${() => this.switchTab("sinks")}>SINKS</button>
        <button class="tab ${this.tab === "webhooks" ? "active" : ""}" @click=${() => this.switchTab("webhooks")}>WEBHOOKS</button>
        <button class="tab ${this.tab === "config"   ? "active" : ""}" @click=${() => this.switchTab("config")}>CONFIG EDITOR</button>
      </div>

      ${this.renderTab()}
    `;
  }

  private renderTab() {
    switch (this.tab) {
      case "wizards":  return html`<dc-setup-wizards></dc-setup-wizards>`;
      case "sinks":    return html`<dc-sinks></dc-sinks>`;
      case "webhooks": return html`<dc-webhooks></dc-webhooks>`;
      case "config":   return this.renderConfigEditor();
    }
  }

  private renderConfigEditor() {
    return html`
      <div class="header">
        <div>
          <div class="dc-section">YAML</div>
          <div class="subtitle dc-hint">Power-user surface — equivalent to the TUI's Config Editor. Wizards write the same file.</div>
        </div>
        <div class="toolbar">
          <span class="meta">${this.path || "—"}</span>
          ${this.dirty ? html`<span class="dirty-pip">● modified</span>` : nothing}
          ${this.renderRevertBtn()}
          <button @click=${() => void this.load()} ?disabled=${this.status.kind === "loading" || this.status.kind === "saving"}>
            RELOAD
          </button>
          <button @click=${() => void this.save()} ?disabled=${!this.dirty || this.status.kind === "saving"}>
            SAVE
          </button>
        </div>
      </div>

      ${this.renderBanner()}

      <div class="editor">
        <textarea
          spellcheck="false"
          autocomplete="off"
          autocapitalize="off"
          .value=${this.text}
          @input=${this.onInput}
          ?disabled=${this.status.kind === "loading"}
        ></textarea>
      </div>
    `;
  }

  private renderBanner() {
    const s = this.status;
    if (s.kind === "loading") {
      return html`<div class="banner">loading config…</div>`;
    }
    if (s.kind === "saving") {
      return html`<div class="banner">writing ${this.path}…</div>`;
    }
    if (s.kind === "error") {
      const isAuth = s.message.includes("401");
      return html`
        <div class="banner err">✗ ${s.message}</div>
        ${isAuth ? this.renderTokenPrompt() : nothing}
      `;
    }
    if (s.kind === "saved") {
      return html`
        <div class="banner ok">
          ✓ saved → ${s.res.path} · backup at ${s.res.backup}
          ${s.res.needs_restart?.length ? html`
            <div class="needs-restart">
              <strong>RESTART REQUIRED FOR:</strong>
              <ul>${s.res.needs_restart.map((r) => html`<li>${r}</li>`)}</ul>
            </div>
          ` : nothing}
        </div>
      `;
    }
    return nothing;
  }
}

declare global {
  interface HTMLElementTagNameMap { "dc-setup": DcSetup; }
}
