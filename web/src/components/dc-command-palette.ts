import { LitElement, html, css, nothing } from "lit";
import { customElement, state, property } from "lit/decorators.js";
import { api, type ApiError } from "../lib/api";

/**
 * Command palette — `:` or `Ctrl+K`. Mirrors the TUI's central navigation
 * model (`internal/tui/palette.go`, ~200 entries against `command.go`'s
 * registry).
 *
 * v1 catalog source: hand-curated nav items + the wizard list fetched from
 * `/v1/setup/wizards`. CLI verbs are out of scope until we expose
 * `GET /v1/commands` (REM-12 follow-up). This still covers the common path:
 * "I want to be on Inventory" / "I want to add an MCP" / "I want to set up
 * Splunk".
 *
 * Keyboard model:
 *   - `Esc` close
 *   - `↑` / `↓` move selection
 *   - `Enter` invoke
 *   - typing filters
 */

interface PaletteEntry {
  id: string;
  label: string;
  category: string;
  hint?: string;
  /** invoked on Enter — return true to keep the palette open */
  invoke: () => void | boolean;
  /** raw text used for fuzzy match (default: label + hint + category) */
  search?: string;
}

interface WizardSpec {
  name: string;
  argv_prefix: string[];
  require_positional: boolean;
}
interface WizardListResponse { wizards: WizardSpec[]; }

const NAV_ITEMS: Array<{ id: string; label: string }> = [
  { id: "overview",  label: "Overview" },
  { id: "alerts",    label: "Alerts" },
  { id: "inventory", label: "Inventory" },
  { id: "policy",    label: "Policy" },
  { id: "audit",     label: "Audit" },
  { id: "logs",      label: "Logs" },
  { id: "setup",     label: "Setup" },
];

@customElement("dc-command-palette")
export class DcCommandPalette extends LitElement {
  static override styles = css`
    :host {
      display: contents;
    }

    .scrim {
      position: fixed;
      inset: 0;
      background: rgba(0, 0, 0, 0.55);
      z-index: 10000;
      display: grid;
      align-items: start;
      justify-items: center;
      padding-top: 12vh;
    }

    .modal {
      width: min(640px, 92vw);
      background: var(--dc-surface-1);
      border: 1px solid var(--dc-primary);
      border-radius: var(--dc-radius-md);
      box-shadow: 0 20px 60px rgba(0, 0, 0, 0.55);
      overflow: hidden;
      display: grid;
      grid-template-rows: auto auto minmax(0, 1fr) auto;
      max-height: 70vh;
    }

    .header {
      padding: 8px 14px;
      border-bottom: 1px solid var(--dc-border);
      background: var(--dc-surface-2);
      color: var(--dc-text-faint);
      font-size: var(--dc-fs-xs);
      letter-spacing: 0.18em;
      text-transform: uppercase;
      display: flex;
      align-items: center;
      justify-content: space-between;
    }
    .header .key {
      color: var(--dc-text-muted);
      font-size: var(--dc-fs-xs);
    }

    input {
      background: var(--dc-bg);
      color: var(--dc-text-bright);
      border: none;
      border-bottom: 1px solid var(--dc-border);
      padding: 14px 16px;
      font-family: var(--dc-font-mono);
      font-size: var(--dc-fs-lg);
      letter-spacing: 0.04em;
      width: 100%;
    }
    input:focus { outline: none; }

    .results {
      overflow-y: auto;
      padding: 4px 0;
    }

    .group-header {
      padding: 8px 16px 4px;
      color: var(--dc-text-faint);
      font-size: var(--dc-fs-xs);
      letter-spacing: 0.18em;
      text-transform: uppercase;
    }

    .row {
      display: grid;
      grid-template-columns: 1fr auto;
      align-items: center;
      gap: 12px;
      padding: 8px 16px;
      cursor: pointer;
      font-family: var(--dc-font-mono);
      font-size: var(--dc-fs-md);
      color: var(--dc-text);
    }
    .row:hover, .row.active {
      background: var(--dc-row-hover);
    }
    .row.active {
      background: var(--dc-surface-2);
      border-left: 2px solid var(--dc-accent);
      padding-left: 14px;
    }
    .label { color: var(--dc-text-bright); }
    .hint  { color: var(--dc-text-muted); font-size: var(--dc-fs-xs); }
    .cat   { color: var(--dc-text-faint); font-size: var(--dc-fs-xs); letter-spacing: 0.10em; text-transform: uppercase; }

    .footer {
      padding: 6px 14px;
      border-top: 1px solid var(--dc-border);
      background: var(--dc-surface-2);
      color: var(--dc-text-faint);
      font-size: var(--dc-fs-xs);
      letter-spacing: 0.10em;
      display: flex;
      gap: var(--dc-space-3);
      flex-wrap: wrap;
    }
    .footer code {
      color: var(--dc-text-muted);
      font-family: var(--dc-font-mono);
      font-size: var(--dc-fs-xs);
    }

    .empty {
      padding: 18px 16px;
      color: var(--dc-text-muted);
      font-style: italic;
      font-size: var(--dc-fs-sm);
    }
  `;

  /** Externally controlled — dc-app toggles this on Ctrl+K / `:` */
  @property({ type: Boolean }) open = false;

  @state() private query = "";
  @state() private wizards: WizardSpec[] = [];
  @state() private activeIdx = 0;

  override connectedCallback(): void {
    super.connectedCallback();
    void this.loadWizards();
  }

  override willUpdate(changed: Map<string, unknown>): void {
    if (changed.has("open") && this.open) {
      this.query = "";
      this.activeIdx = 0;
      // Defer so the input exists when we focus.
      queueMicrotask(() => {
        this.renderRoot?.querySelector("input")?.focus();
      });
    }
  }

  private async loadWizards(): Promise<void> {
    try {
      const res = await api.get<WizardListResponse>("/v1/setup/wizards");
      this.wizards = res.wizards;
    } catch (err) {
      // 401 surfaces via the global token banner; palette gracefully
      // degrades to nav-only.
      void (err as ApiError);
    }
  }

  private close = (): void => {
    this.dispatchEvent(new CustomEvent("dc:palette-close", { bubbles: true, composed: true }));
  };

  private navigate(view: string): void {
    window.location.hash = `#/${view}`;
    this.close();
  }

  private goSetupWizard(name: string): void {
    // Navigate to Setup → Wizards. The Setup component already defaults to
    // the WIZARDS tab; we plant the wizard name in URL hash params so the
    // wizards view can pre-select it.
    window.location.hash = `#/setup?wizard=${encodeURIComponent(name)}`;
    this.close();
  }

  private get entries(): PaletteEntry[] {
    const out: PaletteEntry[] = [];

    for (const n of NAV_ITEMS) {
      out.push({
        id: `nav:${n.id}`,
        label: `Go to ${n.label}`,
        category: "navigate",
        hint: `#/${n.id}`,
        invoke: () => this.navigate(n.id),
      });
    }

    // Setup sub-tab navigation — useful since each tab has distinct
    // operational meaning (wizards / sinks / webhooks / config editor).
    const setupTabs = ["wizards", "sinks", "webhooks", "config"];
    for (const t of setupTabs) {
      out.push({
        id: `nav:setup-${t}`,
        label: `Go to Setup → ${t.charAt(0).toUpperCase() + t.slice(1)}`,
        category: "navigate",
        hint: `#/setup`,
        invoke: () => this.navigate("setup"),
        // Plant the sub-tab in the search blob so typing "sinks" surfaces
        // this row even though the URL is just /setup.
        search: `setup ${t} go to`,
      });
    }

    for (const w of this.wizards) {
      out.push({
        id: `wizard:${w.name}`,
        label: `Run wizard: ${w.name}`,
        category: "setup",
        hint: `defenseclaw ${w.argv_prefix.join(" ")}`,
        invoke: () => this.goSetupWizard(w.name),
      });
    }

    return out;
  }

  private get filtered(): PaletteEntry[] {
    const q = this.query.trim().toLowerCase();
    if (!q) return this.entries;
    const scored: Array<{ e: PaletteEntry; score: number }> = [];
    for (const e of this.entries) {
      const haystack = (e.search ?? `${e.label} ${e.hint ?? ""} ${e.category}`).toLowerCase();
      const score = fuzzyScore(haystack, q);
      if (score > 0) scored.push({ e, score });
    }
    scored.sort((a, b) => b.score - a.score);
    return scored.map((s) => s.e);
  }

  private onKey = (e: KeyboardEvent): void => {
    const rows = this.filtered;
    if (e.key === "Escape") {
      e.preventDefault();
      this.close();
      return;
    }
    if (e.key === "ArrowDown") {
      e.preventDefault();
      this.activeIdx = Math.min(this.activeIdx + 1, Math.max(rows.length - 1, 0));
      return;
    }
    if (e.key === "ArrowUp") {
      e.preventDefault();
      this.activeIdx = Math.max(this.activeIdx - 1, 0);
      return;
    }
    if (e.key === "Enter") {
      e.preventDefault();
      const sel = rows[this.activeIdx];
      if (sel) {
        const keepOpen = sel.invoke();
        if (!keepOpen) this.close();
      }
    }
  };

  private onInput = (e: Event): void => {
    this.query = (e.target as HTMLInputElement).value;
    this.activeIdx = 0;
  };

  override render() {
    if (!this.open) return nothing;
    const rows = this.filtered;
    const grouped = groupBy(rows, (r) => r.category);
    return html`
      <div class="scrim" @click=${(e: Event) => { if (e.target === e.currentTarget) this.close(); }}>
        <div class="modal" role="dialog" aria-label="Command palette">
          <div class="header">
            <span>// COMMAND PALETTE</span>
            <span class="key">esc to close</span>
          </div>
          <input
            type="text"
            placeholder="Type to filter — try ‘alerts’, ‘sinks’, ‘mcp set’…"
            .value=${this.query}
            @input=${this.onInput}
            @keydown=${this.onKey}
            spellcheck="false"
            autocomplete="off"
            autocapitalize="off"
          />
          <div class="results">
            ${rows.length === 0
              ? html`<div class="empty">no matches</div>`
              : Array.from(grouped.entries()).map(([cat, entries]) => html`
                  <div class="group-header">${cat}</div>
                  ${entries.map((e) => {
                    const idx = rows.indexOf(e);
                    return html`
                      <div
                        class="row ${idx === this.activeIdx ? "active" : ""}"
                        @click=${() => { const k = e.invoke(); if (!k) this.close(); }}
                        @mouseenter=${() => { this.activeIdx = idx; }}
                      >
                        <div>
                          <div class="label">${e.label}</div>
                          ${e.hint ? html`<div class="hint">${e.hint}</div>` : nothing}
                        </div>
                        <span class="cat">${e.category}</span>
                      </div>
                    `;
                  })}
                `)
            }
          </div>
          <div class="footer">
            <span>↑↓ <code>navigate</code></span>
            <span>↵ <code>select</code></span>
            <span>esc <code>close</code></span>
            <span>${rows.length} ${rows.length === 1 ? "match" : "matches"}</span>
          </div>
        </div>
      </div>
    `;
  }
}

/**
 * Score a haystack against a query. 0 means no match. Higher is better.
 * Heuristic: prefix > word-boundary > char-in-order > substring.
 */
function fuzzyScore(haystack: string, query: string): number {
  if (haystack.includes(query)) {
    if (haystack.startsWith(query)) return 1000;
    // Word-boundary boost.
    if (new RegExp(`\\b${escapeRe(query)}`).test(haystack)) return 800;
    return 500;
  }
  // Char-in-order match (vim-like).
  let hi = 0;
  for (const c of query) {
    const next = haystack.indexOf(c, hi);
    if (next === -1) return 0;
    hi = next + 1;
  }
  // Score by tightness — fewer skipped chars is better.
  return 100 - (hi - query.length);
}

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function groupBy<T>(xs: T[], key: (x: T) => string): Map<string, T[]> {
  const m = new Map<string, T[]>();
  for (const x of xs) {
    const k = key(x);
    const list = m.get(k) ?? [];
    list.push(x);
    m.set(k, list);
  }
  return m;
}

declare global {
  interface HTMLElementTagNameMap { "dc-command-palette": DcCommandPalette; }
}
