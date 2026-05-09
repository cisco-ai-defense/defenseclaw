import { LitElement, html, css } from "lit";
import { customElement, property } from "lit/decorators.js";

/*
 * dc-panel — base functional container. Mirrors the TUI's RoundedBorder panel
 * with a violet primary border, all-caps title in accent color, and an
 * optional right-side action slot. Body content is supplied via default slot.
 */
@customElement("dc-panel")
export class DcPanel extends LitElement {
  static override styles = css`
    :host {
      display: block;
      background: var(--dc-surface-1);
      border: 1px solid var(--dc-border);
      border-radius: var(--dc-radius-md);
      overflow: hidden;
    }
    :host([accent]) { border-color: var(--dc-primary); }
    :host([critical]) { border-left: 3px solid var(--dc-critical); }

    header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: var(--dc-space-2) var(--dc-space-3);
      border-bottom: 1px solid var(--dc-border);
      background: var(--dc-surface-2);
      gap: var(--dc-space-3);
    }
    .title {
      font-size: var(--dc-fs-sm);
      font-weight: 700;
      letter-spacing: 0.14em;
      color: var(--dc-accent);
      text-transform: uppercase;
    }
    .qualifier {
      font-size: var(--dc-fs-xs);
      color: var(--dc-text-faint);
      letter-spacing: 0.08em;
    }
    .body { padding: var(--dc-space-3); }
    footer {
      padding: var(--dc-space-1) var(--dc-space-3);
      border-top: 1px solid var(--dc-border);
      font-size: var(--dc-fs-xs);
      color: var(--dc-text-faint);
    }
    ::slotted([slot="actions"]) {
      display: inline-flex;
      gap: var(--dc-space-2);
    }
  `;

  @property() heading = "";
  @property() qualifier = "";
  @property({ type: Boolean }) hasFooter = false;

  override render() {
    return html`
      <header>
        <span>
          <span class="title">${this.heading}</span>
          ${this.qualifier ? html`<span class="qualifier"> · ${this.qualifier}</span>` : ""}
        </span>
        <slot name="actions"></slot>
      </header>
      <div class="body"><slot></slot></div>
      ${this.hasFooter ? html`<footer><slot name="footer"></slot></footer>` : ""}
    `;
  }
}

declare global {
  interface HTMLElementTagNameMap { "dc-panel": DcPanel; }
}
