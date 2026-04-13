/**
 * Copyright 2026 Cisco Systems, Inc. and its affiliates
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { HealthMonitor } from "../health-monitor.js";

const statusUrl = "http://127.0.0.1:9999/defenseclaw/status";

/** Invokes the private health check (async). */
function triggerCheck(m: HealthMonitor): Promise<void> {
  return (m as unknown as { check: () => Promise<void> }).check();
}

/** Create a Response that mirrors the real /status JSON. */
function healthyResponse(): Response {
  return new Response(JSON.stringify({ health: { gateway: { state: "running" } } }), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}

function degradedResponse(): Response {
  return new Response(JSON.stringify({ health: { gateway: { state: "starting" } } }), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}

describe("HealthMonitor", () => {
  let originalFetch: typeof globalThis.fetch;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.advanceTimersByTime(10_000);
    globalThis.fetch = originalFetch;
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it("starts as protected", () => {
    const m = new HealthMonitor({ statusUrl });
    expect(m.isUnprotected).toBe(false);
  });

  it("getWarningMessage returns null when healthy", () => {
    const m = new HealthMonitor({ statusUrl });
    expect(m.getWarningMessage()).toBeNull();
  });

  it("marks unprotected when fetch fails", async () => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    globalThis.fetch = vi.fn().mockRejectedValue(new Error("network"));
    const m = new HealthMonitor({ statusUrl });
    await triggerCheck(m);
    expect(m.isUnprotected).toBe(true);
  });

  it("marks unprotected when status is non-200", async () => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    globalThis.fetch = vi.fn().mockResolvedValue(new Response("", { status: 500 }));
    const m = new HealthMonitor({ statusUrl });
    await triggerCheck(m);
    expect(m.isUnprotected).toBe(true);
  });

  it("restores protected when fetch succeeds after failure", async () => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    vi.spyOn(console, "log").mockImplementation(() => {});
    const fetchMock = vi
      .fn()
      .mockRejectedValueOnce(new Error("fail"))
      .mockResolvedValueOnce(healthyResponse());
    globalThis.fetch = fetchMock;
    const m = new HealthMonitor({ statusUrl });
    await triggerCheck(m);
    expect(m.isUnprotected).toBe(true);
    await triggerCheck(m);
    expect(m.isUnprotected).toBe(false);
  });

  it("getWarningMessage returns message when unprotected", async () => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    globalThis.fetch = vi.fn().mockRejectedValue(new Error("down"));
    const m = new HealthMonitor({ statusUrl });
    await triggerCheck(m);
    const msg = m.getWarningMessage();
    expect(msg).not.toBeNull();
    expect(msg).toContain("DEFENSECLAW WARNING");
  });

  it("marks unprotected when gateway state is not running", async () => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    globalThis.fetch = vi.fn().mockResolvedValue(degradedResponse());
    const m = new HealthMonitor({ statusUrl });
    await triggerCheck(m);
    expect(m.isUnprotected).toBe(true);
  });

  it("start and stop lifecycle", async () => {
    const fetchMock = vi.fn().mockResolvedValue(healthyResponse());
    globalThis.fetch = fetchMock;
    const m = new HealthMonitor({ statusUrl, pollIntervalMs: 1000 });
    expect(() => m.start()).not.toThrow();
    await Promise.resolve();
    expect(fetchMock).toHaveBeenCalledTimes(1);

    vi.advanceTimersByTime(1000);
    await Promise.resolve();
    expect(fetchMock).toHaveBeenCalledTimes(2);

    expect(() => m.stop()).not.toThrow();

    vi.advanceTimersByTime(1000);
    await Promise.resolve();
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("does not log duplicate warnings", async () => {
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    globalThis.fetch = vi.fn().mockRejectedValue(new Error("fail"));
    const m = new HealthMonitor({ statusUrl });
    await triggerCheck(m);
    await triggerCheck(m);
    expect(warnSpy).toHaveBeenCalledTimes(1);
  });

  it("includes token in headers when provided", async () => {
    const fetchMock = vi.fn().mockResolvedValue(healthyResponse());
    globalThis.fetch = fetchMock;
    const m = new HealthMonitor({ statusUrl, token: "secret-token" });
    await triggerCheck(m);
    expect(fetchMock).toHaveBeenCalledWith(
      statusUrl,
      expect.objectContaining({
        headers: expect.objectContaining({
          Authorization: "Bearer secret-token",
        }),
      }),
    );
  });
});
