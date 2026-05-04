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
import { join } from "node:path";

vi.mock("node:os", () => ({
  homedir: () => "/mock-home",
}));

vi.mock("node:fs", () => ({
  readFileSync: vi.fn(),
}));

import { readFileSync } from "node:fs";
import { loadSidecarConfig, _resetSidecarConfigCache } from "../sidecar-config.js";

const mockReadFileSync = vi.mocked(readFileSync);

describe("loadSidecarConfig", () => {
  beforeEach(() => {
    _resetSidecarConfigCache();
    mockReadFileSync.mockReset();
  });

  afterEach(() => {
    _resetSidecarConfigCache();
  });

  it("returns defaults when config file is missing", () => {
    mockReadFileSync.mockImplementation(() => {
      throw new Error("ENOENT: no such file or directory");
    });

    const cfg = loadSidecarConfig();
    expect(cfg.host).toBe("127.0.0.1");
    expect(cfg.apiPort).toBe(18970);
    expect(cfg.baseUrl).toBe("http://127.0.0.1:18970");
  });

  it("reads host and api_port from config.yaml", () => {
    mockReadFileSync.mockReturnValue(
      "gateway:\n  host: 10.0.0.5\n  api_port: 9999\n"
    );

    const cfg = loadSidecarConfig();
    expect(cfg.host).toBe("10.0.0.5");
    expect(cfg.apiPort).toBe(9999);
    expect(cfg.baseUrl).toBe("http://10.0.0.5:9999");
    expect(mockReadFileSync).toHaveBeenCalledWith(
      join("/mock-home", ".defenseclaw", "config.yaml"),
      "utf8"
    );
  });

  it("reads approval timeout and hilt flag from config.yaml", () => {
    mockReadFileSync.mockReturnValue(
      "gateway:\n  approval_timeout_s: 45\nguardrail:\n  hilt:\n    enabled: true\n"
    );

    const cfg = loadSidecarConfig();
    expect(cfg.approvalTimeoutS).toBe(45);
    expect(cfg.hiltEnabled).toBe(true);
  });

  it("accepts hitl as an alias for hilt", () => {
    mockReadFileSync.mockReturnValue(
      "guardrail:\n  hitl:\n    enabled: true\n"
    );

    const cfg = loadSidecarConfig();
    expect(cfg.hiltEnabled).toBe(true);
  });

  it("uses default host when only api_port is set", () => {
    mockReadFileSync.mockReturnValue("gateway:\n  api_port: 8080\n");

    const cfg = loadSidecarConfig();
    expect(cfg.host).toBe("127.0.0.1");
    expect(cfg.apiPort).toBe(8080);
    expect(cfg.baseUrl).toBe("http://127.0.0.1:8080");
  });

  it("uses default api_port when only host is set", () => {
    mockReadFileSync.mockReturnValue("gateway:\n  host: 192.168.1.1\n");

    const cfg = loadSidecarConfig();
    expect(cfg.host).toBe("192.168.1.1");
    expect(cfg.apiPort).toBe(18970);
    expect(cfg.baseUrl).toBe("http://192.168.1.1:18970");
  });

  it("returns defaults for empty config file", () => {
    mockReadFileSync.mockReturnValue("");

    const cfg = loadSidecarConfig();
    expect(cfg.host).toBe("127.0.0.1");
    expect(cfg.apiPort).toBe(18970);
  });

  it("returns defaults when gateway section is missing", () => {
    mockReadFileSync.mockReturnValue("audit:\n  enabled: true\n");

    const cfg = loadSidecarConfig();
    expect(cfg.host).toBe("127.0.0.1");
    expect(cfg.apiPort).toBe(18970);
  });

  it("ignores non-numeric api_port", () => {
    mockReadFileSync.mockReturnValue('gateway:\n  api_port: "not-a-number"\n');

    const cfg = loadSidecarConfig();
    expect(cfg.apiPort).toBe(18970);
  });

  it("ignores empty host string", () => {
    mockReadFileSync.mockReturnValue('gateway:\n  host: ""\n');

    const cfg = loadSidecarConfig();
    expect(cfg.host).toBe("127.0.0.1");
  });

  it("caches result across calls", () => {
    mockReadFileSync.mockReturnValue("gateway:\n  api_port: 5555\n");

    const first = loadSidecarConfig();
    const second = loadSidecarConfig();

    expect(first).toBe(second);
    const callsOnFirstLoad = mockReadFileSync.mock.calls.length;
    expect(callsOnFirstLoad).toBeGreaterThanOrEqual(1);

    mockReadFileSync.mockClear();
    loadSidecarConfig();
    expect(mockReadFileSync).toHaveBeenCalledTimes(0);
  });

  it("returns fresh result after cache reset", () => {
    mockReadFileSync.mockReturnValue("gateway:\n  api_port: 5555\n");
    const first = loadSidecarConfig();

    _resetSidecarConfigCache();
    mockReadFileSync.mockReturnValue("gateway:\n  api_port: 6666\n");
    const second = loadSidecarConfig();

    expect(first.apiPort).toBe(5555);
    expect(second.apiPort).toBe(6666);
  });

  it("handles malformed YAML gracefully", () => {
    mockReadFileSync.mockReturnValue("{{invalid yaml");

    const cfg = loadSidecarConfig();
    expect(cfg.host).toBe("127.0.0.1");
    expect(cfg.apiPort).toBe(18970);
  });
});
