import { LitElement, html, css } from "lit";
import { customElement, state } from "lit/decorators.js";

type View = "overview" | "alerts" | "inventory" | "policy"
          | "audit" | "logs" | "setup";

@customElement("dc-app")
export class DcApp extends LitElement {
  static override styles = css`
    :host {
      display: grid;
      grid-template-columns: var(--dc-sidebar-w) minmax(0, 1fr);
      grid-template-rows: 100vh;
      height: 100vh;
      width: 100vw;
    }

    main {
      display: grid;
      grid-template-rows: auto var(--dc-statusbar-h) minmax(0, 1fr);
      min-width: 0;
      min-height: 0;
    }

    .view {
      overflow: auto;
      padding: var(--dc-space-4);
    }

    .placeholder {
      color: var(--dc-text-muted);
      font-style: italic;
      padding: var(--dc-space-5);
      border: 1px dashed var(--dc-border);
      border-radius: var(--dc-radius-md);
    }
  `;

  @state() private view: View = "overview";
  @state() private paletteOpen = false;

  override connectedCallback(): void {
    super.connectedCallback();
    this.syncFromHash();
    window.addEventListener("hashchange", this.syncFromHash);
    window.addEventListener("keydown", this.onGlobalKey);
    this.addEventListener("dc:palette-close", this.closePalette as EventListener);
  }

  override disconnectedCallback(): void {
    super.disconnectedCallback();
    window.removeEventListener("hashchange", this.syncFromHash);
    window.removeEventListener("keydown", this.onGlobalKey);
    this.removeEventListener("dc:palette-close", this.closePalette as EventListener);
  }

  private onGlobalKey = (e: KeyboardEvent): void => {
    // Ctrl/Cmd-K opens unconditionally. `:` opens only when no input/textarea
    // is currently focused (so typing in the YAML editor / filter boxes
    // doesn't ambush the user with a palette).
    const isCmdK = (e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k";
    if (isCmdK) {
      e.preventDefault();
      this.paletteOpen = !this.paletteOpen;
      return;
    }
    if (e.key === ":" && !this.paletteOpen) {
      const target = e.target as HTMLElement | null;
      const isTyping = target instanceof HTMLInputElement
        || target instanceof HTMLTextAreaElement
        || target instanceof HTMLSelectElement
        || (target?.isContentEditable ?? false);
      if (isTyping) return;
      e.preventDefault();
      this.paletteOpen = true;
    }
  };

  private closePalette = (): void => { this.paletteOpen = false; };

  private syncFromHash = (): void => {
    const h = window.location.hash.replace(/^#\/?/, "") as View;
    const valid: View[] = [
      "overview", "alerts", "inventory", "policy",
      "audit", "logs", "setup",
    ];
    if (valid.includes(h)) this.view = h;
  };

  override render() {
    return html`
      <dc-sidebar .active=${this.view}></dc-sidebar>
      <main>
        <dc-token-banner></dc-token-banner>
        <dc-statusbar></dc-statusbar>
        <section class="view">${this.renderView()}</section>
      </main>
      <dc-command-palette .open=${this.paletteOpen}></dc-command-palette>
    `;
  }

  private renderView() {
    switch (this.view) {
      case "overview":  return html`<dc-overview></dc-overview>`;
      case "alerts":    return html`<dc-alerts></dc-alerts>`;
      case "inventory": return html`<dc-inventory></dc-inventory>`;
      case "policy":    return html`<dc-policy></dc-policy>`;
      case "audit":     return html`<dc-audit></dc-audit>`;
      case "logs":      return html`<dc-logs></dc-logs>`;
      case "setup":     return html`<dc-setup></dc-setup>`;
    }
  }
}

declare global {
  interface HTMLElementTagNameMap {
    "dc-app": DcApp;
  }
}
