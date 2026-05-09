import { LitElement, html, css, nothing } from "lit";
import { customElement, state } from "lit/decorators.js";
import { api } from "../lib/api";
import { PollController } from "../lib/poll";

interface BundleEntry {
  kind: string;
  name: string;
  rel_path: string;
  size: number;
  modified: string;
}
interface BundlesResponse {
  dir: string;
  bundles: BundleEntry[] | null;
  count?: number;
  note?: string;
}
interface BundleResponse {
  rel_path: string;
  abs_path: string;
  kind: string;
  size: number;
  modified: string;
  content: string;
}

const KIND_ORDER = ["rego", "guardrail-rule", "suppression", "scanner", "data", "yaml", "other"];
const KIND_LABEL: Record<string, string> = {
  "rego":           "REGO MODULES",
  "guardrail-rule": "GUARDRAIL RULES",
  "suppression":    "SUPPRESSIONS",
  "scanner":        "SCANNER REGISTRATIONS",
  "data":           "DATA OVERLAYS",
  "yaml":           "YAML",
  "other":          "OTHER",
};

/**
 * Policy view — read-only stage (REM-9).
 *
 * Lists bundles from cfg.PolicyDir grouped by kind; right pane shows the
 * raw file content of the selected entry. Edit + test actions are stubbed
 * (greyed) until the PUT/POST endpoints land.
 */
@customElement("dc-policy")
export class DcPolicy extends LitElement {
  static override styles = css`
    :host { display: grid; grid-template-rows: auto minmax(0, 1fr); gap: var(--dc-space-3); height: 100%; min-height: 0; }

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
    .meta { color: var(--dc-text-muted); font-size: var(--dc-fs-xs); letter-spacing: 0.06em; }

    .body {
      display: grid;
      grid-template-columns: 320px minmax(0, 1fr);
      gap: var(--dc-space-3);
      min-height: 0;
    }

    .tree {
      overflow: auto;
      background: var(--dc-surface-1);
      border: 1px solid var(--dc-border);
      border-radius: var(--dc-radius-md);
    }
    .group {
      padding: 8px 12px 4px;
      color: var(--dc-text-faint);
      font-size: var(--dc-fs-xs);
      letter-spacing: 0.14em;
      border-top: 1px solid var(--dc-border);
    }
    .group:first-child { border-top: none; }
    .item {
      display: grid;
      grid-template-columns: 1fr auto;
      gap: 6px;
      align-items: center;
      padding: 5px 12px 5px 18px;
      cursor: pointer;
      font-family: var(--dc-font-mono);
      font-size: var(--dc-fs-sm);
      color: var(--dc-text);
    }
    .item:hover { background: var(--dc-row-hover); }
    .item.active {
      background: var(--dc-surface-2);
      color: var(--dc-text-bright);
      border-left: 2px solid var(--dc-accent);
      padding-left: 16px;
    }
    .path { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .size { color: var(--dc-text-faint); font-size: var(--dc-fs-xs); }

    .viewer {
      display: grid;
      grid-template-rows: auto minmax(0, 1fr);
      background: var(--dc-surface-1);
      border: 1px solid var(--dc-border);
      border-radius: var(--dc-radius-md);
      overflow: hidden;
    }
    .viewer-header {
      display: flex;
      gap: var(--dc-space-3);
      align-items: center;
      padding: 10px 14px;
      background: var(--dc-surface-2);
      border-bottom: 1px solid var(--dc-border);
      font-family: var(--dc-font-mono);
      font-size: var(--dc-fs-sm);
    }
    .viewer-header .name { color: var(--dc-text-bright); font-weight: 700; flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .viewer-header .right { display: flex; align-items: center; gap: var(--dc-space-2); }
    .kind-badge {
      display: inline-block;
      padding: 1px 8px;
      border: 1px solid var(--dc-accent);
      color: var(--dc-accent);
      border-radius: var(--dc-radius-sm);
      font-size: var(--dc-fs-xs);
      letter-spacing: 0.10em;
      text-transform: uppercase;
    }
    button:disabled { opacity: 0.4; cursor: not-allowed; }
    button[title]:hover[disabled] { border-color: var(--dc-border); }

    pre {
      margin: 0;
      padding: var(--dc-space-3);
      background: var(--dc-bg);
      font-family: var(--dc-font-mono);
      font-size: var(--dc-fs-sm);
      color: var(--dc-text);
      white-space: pre;
      overflow: auto;
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
      margin-bottom: var(--dc-space-2);
    }
  `;

  @state() private selectedPath: string | null = null;
  @state() private content: BundleResponse | null = null;
  @state() private contentErr = "";
  @state() private contentLoading = false;

  private listPoll = new PollController<BundlesResponse>(
    this,
    () => api.get<BundlesResponse>("/v1/policy/bundles"),
    30000,
  );

  private async loadContent(rel: string): Promise<void> {
    this.contentLoading = true;
    this.contentErr = "";
    this.content = null;
    try {
      const res = await api.get<BundleResponse>(`/v1/policy/bundle?path=${encodeURIComponent(rel)}`);
      this.content = res;
    } catch (err) {
      this.contentErr = (err as Error).message;
    } finally {
      this.contentLoading = false;
    }
  }

  private select(rel: string): void {
    this.selectedPath = rel;
    void this.loadContent(rel);
  }

  override render() {
    const list = this.listPoll.state.value;
    const err = this.listPoll.state.error;
    const bundles = list?.bundles ?? [];
    const grouped = groupBy(bundles, (b) => b.kind);
    return html`
      <div class="header">
        <div>
          <h1>// POLICY</h1>
          <div class="subtitle dc-hint">
            Operator overlay tree at ${list?.dir ?? "—"}.
            Read-only for now — edit + test land in the next stage.
          </div>
        </div>
        <div class="meta">
          ${bundles.length} bundles
          ${this.listPoll.state.freshness === "stale" ? html` · <span style="color: var(--dc-medium);">stale</span>` : nothing}
        </div>
      </div>

      ${err ? html`<div class="err">✗ ${err.message}</div>` : nothing}
      ${list?.note ? html`<div class="err" style="border-color: var(--dc-medium); color: var(--dc-medium);">⚠ ${list.note}</div>` : nothing}

      <div class="body">
        <div class="tree">${this.renderTree(grouped)}</div>
        <div class="viewer">${this.renderViewer()}</div>
      </div>
    `;
  }

  private renderTree(grouped: Map<string, BundleEntry[]>) {
    if (grouped.size === 0) {
      return html`<div class="empty">no bundles</div>`;
    }
    const sortedKinds = KIND_ORDER.filter((k) => grouped.has(k));
    return sortedKinds.map((kind) => {
      const items = grouped.get(kind) ?? [];
      return html`
        <div class="group">${KIND_LABEL[kind] ?? kind.toUpperCase()}</div>
        ${items.map((b) => html`
          <div
            class="item ${this.selectedPath === b.rel_path ? "active" : ""}"
            @click=${() => this.select(b.rel_path)}
            title=${b.rel_path}
          >
            <span class="path">${b.rel_path}</span>
            <span class="size">${formatBytes(b.size)}</span>
          </div>
        `)}
      `;
    });
  }

  private renderViewer() {
    if (this.contentLoading) return html`<div class="empty">loading…</div>`;
    if (this.contentErr) return html`<div class="empty err">✗ ${this.contentErr}</div>`;
    if (!this.content) {
      return html`<div class="empty">click a bundle on the left to view</div>`;
    }
    const c = this.content;
    return html`
      <div class="viewer-header">
        <span class="kind-badge">${c.kind}</span>
        <span class="name" title=${c.abs_path}>${c.rel_path}</span>
        <span class="right">
          <span class="meta">${formatBytes(c.size)} · ${new Date(c.modified).toLocaleString()}</span>
          <button title="not yet wired — edit endpoint lands in REM-9 stage 2" disabled>EDIT</button>
          <button title="not yet wired — test endpoint lands in REM-9 stage 2" disabled>TEST</button>
        </span>
      </div>
      <pre>${c.content}</pre>
    `;
  }
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

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

declare global {
  interface HTMLElementTagNameMap { "dc-policy": DcPolicy; }
}
