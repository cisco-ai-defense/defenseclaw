/*
 * PollController — Lit ReactiveController that periodically calls a fetcher and
 * exposes { value, error, freshness } to the host. Mirrors the TUI's polling
 * cadence model from the docs:
 *   - 5000ms for cheap reads (health, alerts head)
 *   - 30000ms for expensive reads (audit aggregates, inventory)
 *
 * Components opt into a tier by passing intervalMs. The controller pauses when
 * the document is hidden to avoid wasting cycles in background tabs.
 */
import type { ReactiveController, ReactiveControllerHost } from "lit";

export type Freshness = "live" | "stale" | "loading" | "error";

export interface PollState<T> {
  value: T | null;
  error: Error | null;
  freshness: Freshness;
  lastFetched: number | null;
}

export class PollController<T> implements ReactiveController {
  state: PollState<T> = {
    value: null,
    error: null,
    freshness: "loading",
    lastFetched: null,
  };

  private host: ReactiveControllerHost;
  private fetcher: () => Promise<T>;
  private intervalMs: number;
  private timer: number | null = null;
  private inflight = false;

  constructor(
    host: ReactiveControllerHost,
    fetcher: () => Promise<T>,
    intervalMs = 5000,
  ) {
    this.host = host;
    this.fetcher = fetcher;
    this.intervalMs = intervalMs;
    host.addController(this);
  }

  hostConnected(): void {
    void this.tick();
    this.timer = window.setInterval(() => void this.tick(), this.intervalMs);
    document.addEventListener("visibilitychange", this.onVisibility);
  }

  hostDisconnected(): void {
    if (this.timer !== null) window.clearInterval(this.timer);
    this.timer = null;
    document.removeEventListener("visibilitychange", this.onVisibility);
  }

  refresh(): Promise<void> { return this.tick(); }

  private onVisibility = (): void => {
    if (document.hidden) return;
    void this.tick();
  };

  private async tick(): Promise<void> {
    if (this.inflight || document.hidden) return;
    this.inflight = true;
    try {
      const value = await this.fetcher();
      this.state = {
        value,
        error: null,
        freshness: "live",
        lastFetched: Date.now(),
      };
    } catch (err) {
      this.state = {
        ...this.state,
        error: err as Error,
        freshness: this.state.value ? "stale" : "error",
      };
    } finally {
      this.inflight = false;
      this.host.requestUpdate();
    }
  }
}
