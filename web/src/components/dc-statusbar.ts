import { LitElement, html, css } from "lit";
import { customElement } from "lit/decorators.js";
import { api, type Health, type SubsystemState } from "../lib/api";
import { PollController } from "../lib/poll";

const DOT_RUNNING  = "●";
const DOT_OFF      = "○";

function dotColor(state: SubsystemState | undefined): string {
  switch (state) {
    case "running":      return "var(--dc-clean)";
    case "starting":
    case "reconnecting":
    case "degraded":     return "var(--dc-medium)";
    case "error":
    case "stopped":      return "var(--dc-critical)";
    default:             return "var(--dc-text-faint)";
  }
}

function dotGlyph(state: SubsystemState | undefined): string {
  return state === "running" || state === "degraded" || state === "starting" || state === "reconnecting"
    ? DOT_RUNNING
    : DOT_OFF;
}

function fmtUptime(ms: number): string {
  const s = Math.floor(ms / 1000);
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = s % 60;
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m ${sec}s`;
  return `${sec}s`;
}

@customElement("dc-statusbar")
export class DcStatusbar extends LitElement {
  static override styles = css`
    :host {
      display: flex;
      align-items: center;
      gap: var(--dc-space-4);
      height: var(--dc-statusbar-h);
      padding: 0 var(--dc-space-4);
      background: var(--dc-surface-1);
      border-bottom: 1px solid var(--dc-border);
      font-size: var(--dc-fs-sm);
      letter-spacing: 0.06em;
      overflow-x: auto;
      white-space: nowrap;
    }
    .pill {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      color: var(--dc-text-muted);
    }
    .label { color: var(--dc-text-faint); }
    .value { color: var(--dc-text); }
    .freshness { margin-left: auto; }
  `;

  private poll = new PollController<Health>(
    this,
    () => api.get<Health>("/health"),
    5000,
  );

  override render() {
    const h = this.poll.state.value;
    const fresh = this.poll.state.freshness;

    if (!h) {
      return html`
        <span class="pill">
          <span style="color: ${dotColor("stopped")};">${DOT_OFF}</span>
          <span class="label">SIDECAR</span>
          <span class="value">${fresh === "loading" ? "loading…" : "offline"}</span>
        </span>
      `;
    }

    const items: Array<[string, SubsystemState | undefined, string]> = [
      ["GATEWAY",   h.gateway?.state,   ""],
      ["GUARDRAIL", h.guardrail?.state, String(h.guardrail?.details?.["mode"] ?? "")],
      ["WATCHER",   h.watcher?.state,   ""],
      ["SINKS",     h.sinks?.state,     ""],
      ["TELEMETRY", h.telemetry?.state, ""],
    ];

    return html`
      ${items.map(([label, state, extra]) => html`
        <span class="pill">
          <span style="color: ${dotColor(state)};">${dotGlyph(state)}</span>
          <span class="label">${label}</span>
          <span class="value">${state ?? "—"}${extra ? ` / ${extra}` : ""}</span>
        </span>
      `)}
      <span class="pill freshness">
        <span class="label">UPTIME</span>
        <span class="value">${fmtUptime(h.uptime_ms)}</span>
      </span>
      <span class="pill">
        <span class="label">v</span>
        <span class="value">${h.provenance?.binary_version ?? "?"}</span>
      </span>
    `;
  }
}

declare global {
  interface HTMLElementTagNameMap { "dc-statusbar": DcStatusbar; }
}
