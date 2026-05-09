import { LitElement, html, css } from "lit";
import { customElement, property } from "lit/decorators.js";

interface NavItem { id: string; label: string; key: string; }
interface NavGroup { title: string; items: NavItem[]; }

const GROUPS: NavGroup[] = [
  {
    title: "OPERATE",
    items: [
      { id: "overview",  label: "OVERVIEW",  key: "1" },
      { id: "alerts",    label: "ALERTS",    key: "2" },
      { id: "inventory", label: "INVENTORY", key: "3" },
      { id: "policy",    label: "POLICY",    key: "4" },
    ],
  },
  {
    title: "EVIDENCE",
    items: [
      { id: "audit", label: "AUDIT", key: "5" },
      { id: "logs",  label: "LOGS",  key: "6" },
      { id: "setup", label: "SETUP", key: "7" },
    ],
  },
];

@customElement("dc-sidebar")
export class DcSidebar extends LitElement {
  static override styles = css`
    :host {
      display: flex;
      flex-direction: column;
      gap: var(--dc-space-4);
      padding: var(--dc-space-3);
      background: var(--dc-surface-1);
      border-right: 1px solid var(--dc-border);
      overflow-y: auto;
    }

    .brand {
      display: flex;
      align-items: baseline;
      gap: var(--dc-space-2);
      padding: var(--dc-space-2) 0;
      border-bottom: 1px solid var(--dc-border);
    }
    .brand-mark {
      font-weight: 700;
      color: var(--dc-accent);
      letter-spacing: 0.18em;
    }
    .brand-sub {
      font-size: var(--dc-fs-xs);
      color: var(--dc-text-faint);
      letter-spacing: 0.10em;
      text-transform: uppercase;
    }

    .group { display: flex; flex-direction: column; gap: var(--dc-space-1); }
    .group-title {
      font-size: var(--dc-fs-xs);
      color: var(--dc-text-faint);
      letter-spacing: 0.18em;
      padding: 0 var(--dc-space-2) var(--dc-space-1);
    }

    .nav-item {
      display: grid;
      grid-template-columns: 18px 1fr;
      align-items: center;
      gap: var(--dc-space-2);
      padding: 6px var(--dc-space-2);
      border: 1px solid transparent;
      border-radius: var(--dc-radius-sm);
      color: var(--dc-text-muted);
      letter-spacing: 0.10em;
      cursor: pointer;
    }
    .nav-item:hover { background: var(--dc-row-hover); color: var(--dc-text); }
    .nav-item.active {
      color: var(--dc-text-bright);
      background: var(--dc-surface-2);
      border-color: var(--dc-primary);
    }
    .key {
      color: var(--dc-text-faint);
      font-size: var(--dc-fs-xs);
    }
    .nav-item.active .key { color: var(--dc-accent); }

    .footer {
      margin-top: auto;
      padding-top: var(--dc-space-2);
      border-top: 1px solid var(--dc-border);
      font-size: var(--dc-fs-xs);
      color: var(--dc-text-faint);
      line-height: 1.5;
    }
  `;

  @property({ type: String }) active = "overview";

  override render() {
    return html`
      <div class="brand">
        <span class="brand-mark">DEFENSECLAW</span>
        <span class="brand-sub">v0.1</span>
      </div>
      ${GROUPS.map((g) => html`
        <div class="group">
          <div class="group-title">${g.title}</div>
          ${g.items.map((it) => html`
            <a class="nav-item ${this.active === it.id ? "active" : ""}"
               href="#/${it.id}">
              <span class="key">${it.key}</span>
              <span>${it.label}</span>
            </a>
          `)}
        </div>
      `)}
      <div class="footer">
        <div class="dc-hint">: or ctrl+k for palette</div>
        <div>? for help</div>
      </div>
    `;
  }
}

declare global {
  interface HTMLElementTagNameMap { "dc-sidebar": DcSidebar; }
}
