import { LitElement, html, css, nothing } from "lit";
import { customElement, state } from "lit/decorators.js";
import { setToken } from "../lib/api";

/**
 * Global auth banner. Listens for "dc:auth-failure" events from the api
 * client and surfaces a prompt for $DEFENSECLAW_GATEWAY_TOKEN. Dismissed
 * once a token is saved (with page reload to flush PollController state)
 * or via the X button.
 *
 * The banner pins to the top of the main viewport, above dc-statusbar,
 * because it's cross-cutting state that any view can trigger.
 */
@customElement("dc-token-banner")
export class DcTokenBanner extends LitElement {
  static override styles = css`
    :host { display: block; }

    .banner {
      display: grid;
      grid-template-columns: auto 1fr auto auto;
      gap: var(--dc-space-3);
      align-items: center;
      padding: 10px 16px;
      background: var(--dc-surface-2);
      border-bottom: 2px solid var(--dc-medium);
      font-family: var(--dc-font-mono);
      font-size: var(--dc-fs-sm);
    }
    .icon {
      color: var(--dc-medium);
      font-weight: 700;
      letter-spacing: 0.10em;
    }
    .msg { color: var(--dc-text); }
    .msg .hint {
      display: block;
      color: var(--dc-text-faint);
      font-size: var(--dc-fs-xs);
      margin-top: 2px;
    }
    form {
      display: flex;
      gap: var(--dc-space-2);
      align-items: center;
    }
    input {
      background: var(--dc-bg);
      color: var(--dc-text);
      border: 1px solid var(--dc-border);
      border-radius: var(--dc-radius-sm);
      padding: 6px 10px;
      font-family: var(--dc-font-mono);
      font-size: var(--dc-fs-md);
      min-width: 280px;
    }
    input:focus { outline: none; border-color: var(--dc-primary); }
    button.dismiss {
      padding: 4px 10px;
      color: var(--dc-text-muted);
    }
  `;

  @state() private visible = false;
  @state() private lastPath = "";
  @state() private dismissed = false;

  override connectedCallback(): void {
    super.connectedCallback();
    window.addEventListener("dc:auth-failure", this.onAuthFailure as EventListener);
    // Probe on mount: if the user has no token saved, surface the banner
    // proactively so they don't have to wait for a 401 to render.
    if (!localStorage.getItem("dc.token")) {
      this.visible = true;
    }
  }

  override disconnectedCallback(): void {
    super.disconnectedCallback();
    window.removeEventListener("dc:auth-failure", this.onAuthFailure as EventListener);
  }

  private onAuthFailure = (e: Event): void => {
    if (this.dismissed) return;
    const ev = e as CustomEvent<{ path: string }>;
    this.lastPath = ev.detail?.path ?? "";
    this.visible = true;
  };

  private onSubmit = (e: Event): void => {
    e.preventDefault();
    const form = e.target as HTMLFormElement;
    const input = form.elements.namedItem("token") as HTMLInputElement | null;
    const v = input?.value.trim() ?? "";
    if (!v) return;
    setToken(v);
    // Hard reload — every PollController throws away its cached error and
    // re-fetches with the new auth header, simpler than threading a
    // refresh-all event through every component.
    window.location.reload();
  };

  private dismiss = (): void => {
    this.dismissed = true;
    this.visible = false;
  };

  override render() {
    if (!this.visible) return nothing;
    return html`
      <div class="banner" role="alert">
        <span class="icon">// AUTH REQUIRED</span>
        <span class="msg">
          Gateway has token auth on. Paste <code>$DEFENSECLAW_GATEWAY_TOKEN</code> to unblock the dashboard.
          ${this.lastPath ? html`<span class="hint">last failure: ${this.lastPath}</span>` : nothing}
        </span>
        <form @submit=${this.onSubmit}>
          <input
            type="password"
            name="token"
            placeholder="bearer token"
            autocomplete="off"
            spellcheck="false"
            autofocus
          />
          <button type="submit">SAVE &amp; RELOAD</button>
        </form>
        <button class="dismiss" @click=${this.dismiss} title="dismiss until next refresh">×</button>
      </div>
    `;
  }
}

declare global {
  interface HTMLElementTagNameMap { "dc-token-banner": DcTokenBanner; }
}
