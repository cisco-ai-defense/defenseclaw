import { LitElement, html, css, nothing } from "lit";
import { customElement, state } from "lit/decorators.js";
import { api, type ApiError } from "../lib/api";
import { PollController } from "../lib/poll";

type Scope = "all" | "skills" | "mcps" | "plugins" | "tools";

interface ActionResponse {
  ok: boolean;
  exit_code: number;
  argv: string[];
  output: string;
}

// Per-kind allowed action verbs. Mirrors the server-side allowlists in
// internal/gateway/api_query.go (handleV1{Skill,MCP,Plugin}Action) and the
// TUI's actionmenu.go vocabulary. "tool" has no mutating actions today.
const KIND_ACTIONS: Record<string, ReadonlyArray<string>> = {
  skill:  ["scan", "allow", "block", "quarantine", "restore", "disable", "enable"],
  mcp:    ["scan", "allow", "block", "quarantine", "restore", "disable", "enable"],
  plugin: ["scan", "install", "disable", "enable"],
  tool:   [],
};
const DESTRUCTIVE = new Set(["block", "quarantine", "remove"]);

interface SkillRow   { key?: string; name?: string; trust?: string; verdict?: string; quarantined?: boolean; [k: string]: unknown; }
interface MCPRow     { name: string; url?: string; transport?: string; allowed?: boolean; [k: string]: unknown; }
interface PluginRow  { name: string; path: string; has_manifest: boolean; }
interface ToolRow    { name?: string; tool_name?: string; mcp?: string; server?: string; [k: string]: unknown; }

interface SkillsResponse  { skills?: SkillRow[]; }
interface MCPsResponse    { mcps?: MCPRow[];     servers?: MCPRow[]; }
interface PluginsResponse { plugins: PluginRow[]; dir: string; count: number; }
interface ToolsResponse   { tools?: ToolRow[]; catalog?: ToolRow[]; }

interface UnifiedRow {
  kind: "skill" | "mcp" | "plugin" | "tool";
  name: string;
  status: string;
  detail: string;
  raw: unknown;
}

const SCOPES: Array<{ id: Scope; label: string }> = [
  { id: "all",     label: "ALL" },
  { id: "skills",  label: "SKILLS" },
  { id: "mcps",    label: "MCPS" },
  { id: "plugins", label: "PLUGINS" },
  { id: "tools",   label: "TOOLS" },
];

@customElement("dc-inventory")
export class DcInventory extends LitElement {
  static override styles = css`
    :host { display: grid; grid-template-rows: auto auto auto minmax(0,1fr); gap: var(--dc-space-3); height: 100%; min-height: 0; }

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

    .scope-bar {
      display: flex;
      gap: var(--dc-space-2);
      align-items: center;
      flex-wrap: wrap;
    }
    .chip {
      padding: 4px 12px;
      background: transparent;
      color: var(--dc-text-muted);
      border: 1px solid var(--dc-border);
      border-radius: var(--dc-radius-sm);
      font-family: var(--dc-font-mono);
      font-size: var(--dc-fs-xs);
      letter-spacing: 0.10em;
      cursor: pointer;
    }
    .chip:hover { color: var(--dc-text); border-color: var(--dc-primary); }
    .chip.active {
      color: var(--dc-text-bright);
      background: var(--dc-surface-2);
      border-color: var(--dc-accent);
    }

    .filter-bar {
      display: grid;
      grid-template-columns: 1fr auto;
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

    .table-wrap {
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
    }
    th {
      background: var(--dc-surface-2);
      color: var(--dc-text-faint);
      font-weight: 700;
      letter-spacing: 0.10em;
      text-transform: uppercase;
      font-size: var(--dc-fs-xs);
    }
    td.kind {
      color: var(--dc-accent);
      letter-spacing: 0.10em;
      text-transform: uppercase;
      font-size: var(--dc-fs-xs);
    }
    td.name { color: var(--dc-text-bright); font-weight: 700; }
    td.detail { color: var(--dc-text-muted); font-size: var(--dc-fs-xs); }
    td.actions { white-space: nowrap; text-align: right; }
    .stats { color: var(--dc-text-muted); font-size: var(--dc-fs-xs); letter-spacing: 0.06em; }

    button.action {
      padding: 3px 9px;
      font-size: var(--dc-fs-xs);
      letter-spacing: 0.08em;
      margin-left: 4px;
    }
    button.action.danger { color: var(--dc-critical); }
    button.action.danger:hover { border-color: var(--dc-critical); }
    button.action:disabled { opacity: 0.4; cursor: not-allowed; }

    .banner {
      padding: var(--dc-space-2) var(--dc-space-3);
      border: 1px solid var(--dc-border);
      border-radius: var(--dc-radius-sm);
      font-size: var(--dc-fs-sm);
      margin-bottom: var(--dc-space-2);
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

    .empty {
      padding: var(--dc-space-5);
      color: var(--dc-text-muted);
      font-style: italic;
      text-align: center;
    }
  `;

  @state() private scope: Scope = "all";
  @state() private filterText = "";
  @state() private busyKey = "";
  @state() private lastResult: { kind: string; name: string; action: string; res: ActionResponse | { error: string } } | null = null;

  private skills   = new PollController<SkillsResponse>(this,  () => api.get<SkillsResponse>("/skills"),       30000);
  private mcps     = new PollController<MCPsResponse>(this,    () => api.get<MCPsResponse>("/mcps"),           30000);
  private plugins  = new PollController<PluginsResponse>(this, () => api.get<PluginsResponse>("/v1/plugins"),  30000);
  private tools    = new PollController<ToolsResponse>(this,   () => api.get<ToolsResponse>("/tools/catalog"), 30000);

  private async runAction(kind: string, name: string, action: string): Promise<void> {
    if (DESTRUCTIVE.has(action) && !confirm(`${action.toUpperCase()} ${kind} "${name}"?`)) return;
    const path = `/v1/${kind}s/${encodeURIComponent(name)}/${action}`;
    this.busyKey = `${kind}:${name}:${action}`;
    this.lastResult = null;
    try {
      const res = await api.post<ActionResponse>(path);
      this.lastResult = { kind, name, action, res };
      // Refresh the source list for the affected kind so toggled state reflects.
      if (kind === "skill")  void this.skills.refresh();
      if (kind === "mcp")    void this.mcps.refresh();
      if (kind === "plugin") void this.plugins.refresh();
    } catch (err) {
      const e = err as ApiError;
      this.lastResult = {
        kind, name, action,
        res: { error: e.status ? `HTTP ${e.status}` : e.message },
      };
    } finally {
      this.busyKey = "";
    }
  }

  private get rows(): UnifiedRow[] {
    const out: UnifiedRow[] = [];

    const skills = this.skills.state.value?.skills ?? [];
    for (const s of skills) {
      const name = s.name ?? s.key ?? "(unnamed)";
      out.push({
        kind: "skill",
        name: String(name),
        status: s.quarantined ? "quarantined" : (s.verdict ?? s.trust ?? "—"),
        detail: pickDetail(s, ["source", "version", "verdict_severity"]),
        raw: s,
      });
    }

    const mcps = this.mcps.state.value?.mcps ?? this.mcps.state.value?.servers ?? [];
    for (const m of mcps) {
      out.push({
        kind: "mcp",
        name: m.name,
        status: m.allowed === false ? "blocked" : (m.transport ?? "—"),
        detail: m.url ?? pickDetail(m, ["command", "transport"]),
        raw: m,
      });
    }

    const plugins = this.plugins.state.value?.plugins ?? [];
    for (const p of plugins) {
      out.push({
        kind: "plugin",
        name: p.name,
        status: p.has_manifest ? "manifest" : "—",
        detail: p.path,
        raw: p,
      });
    }

    const tools = this.tools.state.value?.tools ?? this.tools.state.value?.catalog ?? [];
    for (const t of tools) {
      const name = t.tool_name ?? t.name ?? "(unnamed)";
      out.push({
        kind: "tool",
        name: String(name),
        status: String(t.mcp ?? t.server ?? "—"),
        detail: pickDetail(t, ["description", "summary"]),
        raw: t,
      });
    }

    return out;
  }

  private get visible(): UnifiedRow[] {
    let rows = this.rows;
    if (this.scope !== "all") {
      const want = this.scope.replace(/s$/, "");
      rows = rows.filter((r) => r.kind === want);
    }
    if (this.filterText.trim()) {
      const q = this.filterText.trim().toLowerCase();
      rows = rows.filter((r) =>
        r.name.toLowerCase().includes(q)
        || r.status.toLowerCase().includes(q)
        || r.detail.toLowerCase().includes(q)
      );
    }
    return rows;
  }

  private get countsByKind(): Record<string, number> {
    const c = { skill: 0, mcp: 0, plugin: 0, tool: 0 } as Record<string, number>;
    for (const r of this.rows) c[r.kind]++;
    return c;
  }

  override render() {
    const c = this.countsByKind;
    const total = this.rows.length;
    return html`
      <div class="header">
        <div>
          <h1>// INVENTORY</h1>
          <div class="subtitle dc-hint">
            Skills + MCP servers + plugins + tools, unified. Filter by scope chip or substring search.
          </div>
        </div>
        <div class="stats">
          ${c.skill} skills · ${c.mcp} mcps · ${c.plugin} plugins · ${c.tool} tools
        </div>
      </div>

      <div class="scope-bar">
        ${SCOPES.map((s) => {
          const count = s.id === "all" ? total : c[s.id.replace(/s$/, "")] ?? 0;
          return html`
            <button
              class="chip ${this.scope === s.id ? "active" : ""}"
              @click=${() => { this.scope = s.id; }}
            >${s.label} · ${count}</button>
          `;
        })}
      </div>

      <div class="filter-bar">
        <input
          type="text"
          placeholder="filter by name, status, or detail…"
          .value=${this.filterText}
          @input=${(e: Event) => { this.filterText = (e.target as HTMLInputElement).value; }}
        />
        <button @click=${() => { this.filterText = ""; }}>CLEAR</button>
      </div>

      ${this.renderResultBanner()}
      <div class="table-wrap">${this.renderTable()}</div>
    `;
  }

  private renderResultBanner() {
    if (!this.lastResult) return nothing;
    const { kind, name, action, res } = this.lastResult;
    if ("error" in res) {
      return html`<div class="banner err">✗ ${kind} ${name} · ${action} → ${res.error}</div>`;
    }
    const ok = res.ok;
    return html`
      <div class="banner ${ok ? "ok" : "err"}">
        ${ok ? "✓" : "✗"} ${kind} ${name} · ${action} → exit ${res.exit_code}
        ${res.output ? html`<pre class="output">${res.output}</pre>` : nothing}
      </div>
    `;
  }

  private renderTable() {
    const rows = this.visible;
    if (rows.length === 0) {
      return html`<div class="empty">no items match · widen the scope or clear the filter</div>`;
    }
    return html`
      <table>
        <thead>
          <tr><th>Kind</th><th>Name</th><th>Status</th><th>Detail</th><th>Actions</th></tr>
        </thead>
        <tbody>
          ${rows.map((r) => html`
            <tr>
              <td class="kind">${r.kind}</td>
              <td class="name">${r.name}</td>
              <td>${r.status}</td>
              <td class="detail" title=${r.detail}>${r.detail}</td>
              <td class="actions">${this.renderActions(r.kind, r.name)}</td>
            </tr>
          `)}
        </tbody>
      </table>
    `;
  }

  private renderActions(kind: string, name: string) {
    const verbs = KIND_ACTIONS[kind] ?? [];
    if (verbs.length === 0) return html`<span style="color: var(--dc-text-faint); font-style: italic; font-size: var(--dc-fs-xs);">—</span>`;
    const anyBusy = !!this.busyKey;
    return verbs.map((a) => {
      const busy = this.busyKey === `${kind}:${name}:${a}`;
      const danger = DESTRUCTIVE.has(a);
      return html`
        <button
          class="action ${danger ? "danger" : ""}"
          ?disabled=${anyBusy}
          @click=${() => void this.runAction(kind, name, a)}
          title=${a}
        >${busy ? "…" : a.toUpperCase()}</button>
      `;
    });
  }
}

function pickDetail(o: Record<string, unknown>, keys: string[]): string {
  for (const k of keys) {
    const v = o[k];
    if (v !== undefined && v !== null && v !== "") return String(v);
  }
  return "—";
}

declare global {
  interface HTMLElementTagNameMap { "dc-inventory": DcInventory; }
}
