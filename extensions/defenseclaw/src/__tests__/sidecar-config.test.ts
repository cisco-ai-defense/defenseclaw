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
  userInfo: () => ({ homedir: "/mock-home" }),
}));

vi.mock("node:child_process", () => ({ execFileSync: vi.fn() }));

vi.mock("node:fs", () => ({
  readFileSync: vi.fn(),
  statSync: vi.fn(),
}));

import { readFileSync, statSync } from "node:fs";
import { execFileSync } from "node:child_process";
import {
  configureSidecarConnection,
  loadSidecarConfig,
  loadOpenClawOutageMode,
  separateUserLayout,
  setRuntimeSettings,
  _resetSidecarConfigCache,
} from "../sidecar-config.js";

const mockReadFileSync = vi.mocked(readFileSync);
const mockStatSync = vi.mocked(statSync);
const mockExecFileSync = vi.mocked(execFileSync);

describe("loadOpenClawOutageMode", () => {
  beforeEach(() => mockExecFileSync.mockReset());
  afterEach(() => mockExecFileSync.mockReset());

  it.each([
    ["default or permissive", "open\n", "open"],
    ["strict or managed", "closed\n", "closed"],
  ] as const)("uses the installed resolver for %s", (_tier, answer, expected) => {
    mockExecFileSync.mockReturnValue(answer);
    expect(loadOpenClawOutageMode()).toBe(expected);
    expect(mockExecFileSync).toHaveBeenCalledWith(
      "/mock-home/.local/bin/defenseclaw-gateway",
      ["hook-outage-mode", "--connector", "openclaw", "--hook-dir", "/mock-home/.defenseclaw/hooks"],
      expect.objectContaining({ env: { HOME: "/mock-home", PATH: "/usr/bin:/bin" } }),
    );
  });

  it("closes on an unreadable resolver answer", () => {
    mockExecFileSync.mockImplementation(() => { throw new Error("unavailable"); });
    expect(loadOpenClawOutageMode()).toBe("closed");
  });

  it("binds the answer to the active custom data root in both tier orientations", () => {
    const previous = process.env.DEFENSECLAW_HOME;
    process.env.DEFENSECLAW_HOME = "/active-root";
    try {
      for (const answer of ["open\n", "closed\n"]) {
        mockExecFileSync.mockReturnValue(answer);
        expect(loadOpenClawOutageMode()).toBe(answer.trim());
        expect(mockExecFileSync).toHaveBeenLastCalledWith(
          "/mock-home/.local/bin/defenseclaw-gateway",
          ["hook-outage-mode", "--connector", "openclaw", "--hook-dir", "/active-root/hooks"],
          expect.objectContaining({ env: expect.objectContaining({ DEFENSECLAW_HOME: "/active-root" }) }),
        );
      }
    } finally {
      if (previous === undefined) delete process.env.DEFENSECLAW_HOME;
      else process.env.DEFENSECLAW_HOME = previous;
    }
  });

  it("uses the saved resolver for a per-user Windows install", () => {
    const previous = Object.getOwnPropertyDescriptor(process, "platform");
    Object.defineProperty(process, "platform", { value: "win32", configurable: true });
    try {
      mockExecFileSync.mockReturnValue("open\n");
      expect(loadOpenClawOutageMode()).toBe("open");
      expect(mockExecFileSync).toHaveBeenCalledWith(
        "/mock-home/.local/bin/defenseclaw-gateway.exe",
        ["hook-outage-mode", "--connector", "openclaw", "--hook-dir", "/mock-home/.defenseclaw/hooks"],
        expect.objectContaining({ env: expect.objectContaining({ USERPROFILE: "/mock-home" }) }),
      );
    } finally {
      if (previous) Object.defineProperty(process, "platform", previous);
    }
  });
});

describe("loadSidecarConfig", () => {
  const savedDefenseClawHome = process.env.DEFENSECLAW_HOME;
  const savedE2EGatewayToken = process.env.E2E_GATEWAY_TOKEN;

  beforeEach(() => {
    _resetSidecarConfigCache();
    mockReadFileSync.mockReset();
    mockStatSync.mockReset();
    mockStatSync.mockImplementation(() => {
      throw new Error("ENOENT");
    });
    delete process.env.DEFENSECLAW_HOME;
    delete process.env.E2E_GATEWAY_TOKEN;
  });

  afterEach(() => {
    _resetSidecarConfigCache();
    if (savedDefenseClawHome === undefined) {
      delete process.env.DEFENSECLAW_HOME;
    } else {
      process.env.DEFENSECLAW_HOME = savedDefenseClawHome;
    }
    if (savedE2EGatewayToken === undefined) {
      delete process.env.E2E_GATEWAY_TOKEN;
    } else {
      process.env.E2E_GATEWAY_TOKEN = savedE2EGatewayToken;
    }
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

  it("reads config and the plugin credential from an absolute DEFENSECLAW_HOME", () => {
    process.env.DEFENSECLAW_HOME = "/isolated-defenseclaw";
    mockReadFileSync.mockImplementation((path) => {
      const selectedPath = String(path);
      if (selectedPath === join("/isolated-defenseclaw", "config.yaml")) {
        return "gateway:\n  host: 10.0.0.8\n";
      }
      if (selectedPath === join("/isolated-defenseclaw", "hooks", ".hook-openclaw.token")) {
        return "a".repeat(64) + "\n";
      }
      throw new Error(`unexpected path: ${selectedPath}`);
    });

    const cfg = loadSidecarConfig();
    expect(cfg.host).toBe("10.0.0.8");
    expect(cfg.token).toBe("a".repeat(64));
    expect(mockReadFileSync).not.toHaveBeenCalledWith(
      join("/mock-home", ".defenseclaw", "config.yaml"),
      "utf8"
    );
  });

  it("uses the default home when DEFENSECLAW_HOME is empty", () => {
    process.env.DEFENSECLAW_HOME = "";
    mockReadFileSync.mockImplementation((path) => {
      const selectedPath = String(path);
      if (selectedPath === join("/mock-home", ".defenseclaw", "config.yaml")) {
        return "gateway:\n  host: 127.0.0.2\n";
      }
      throw new Error(`unexpected path: ${selectedPath}`);
    });

    expect(loadSidecarConfig().host).toBe("127.0.0.2");
    expect(mockReadFileSync).toHaveBeenCalledWith(
      join("/mock-home", ".defenseclaw", "config.yaml"),
      "utf8"
    );
  });

  it("rejects a relative DEFENSECLAW_HOME without reading persistent state", () => {
    process.env.DEFENSECLAW_HOME = "relative/state";

    expect(() => loadSidecarConfig()).toThrow(
      "DEFENSECLAW_HOME must be an absolute path"
    );
    expect(mockReadFileSync).not.toHaveBeenCalled();
  });

  it("rejects a whitespace DEFENSECLAW_HOME without reading persistent state", () => {
    process.env.DEFENSECLAW_HOME = "   ";

    expect(() => loadSidecarConfig()).toThrow(
      "DEFENSECLAW_HOME must be an absolute path"
    );
    expect(mockReadFileSync).not.toHaveBeenCalled();
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

  // -------------------------------------------------------------------
  // S3.HIGH_BUG ("Embedded OpenClaw plugin misses the canonical
  // first-boot token"): the embedded extension's token resolver MUST
  // accept the canonical DEFENSECLAW_GATEWAY_TOKEN written by the Go
  // sidecar's first-boot bootstrap into ~/.defenseclaw/.env, even when
  // the operator never exported the value into the Node process. Before
  // the fix the dotenv fallback only looked for OPENCLAW_GATEWAY_TOKEN
  // and the OpenClaw process had no token, which silently 401'd every
  // /api/v1/inspect/* request and let tool calls bypass inspection.
  // -------------------------------------------------------------------
  describe("plugin credential", () => {
    const TOKEN = "e".repeat(64);
    const savedEnv: Record<string, string | undefined> = {};
    const ENV_KEYS = ["DEFENSECLAW_GATEWAY_TOKEN", "OPENCLAW_GATEWAY_TOKEN"] as const;

    beforeEach(() => {
      for (const k of ENV_KEYS) savedEnv[k] = process.env[k];
    });

    afterEach(() => {
      for (const k of ENV_KEYS) {
        if (savedEnv[k] === undefined) delete process.env[k];
        else process.env[k] = savedEnv[k];
      }
    });

    function serve(files: Record<string, string>) {
      mockReadFileSync.mockImplementation((path) => {
        const p = String(path);
        for (const [suffix, body] of Object.entries(files)) {
          if (p.endsWith(suffix)) return body;
        }
        throw new Error("ENOENT: " + p);
      });
    }

    it("reads the openclaw scoped token from hooks/.hook-openclaw.token", () => {
      serve({ "config.yaml": "", ".hook-openclaw.token": TOKEN + "\n" });
      expect(loadSidecarConfig().token).toBe(TOKEN);
    });

    it("never uses the master gateway token or the OpenClaw gateway token", () => {
      process.env.DEFENSECLAW_GATEWAY_TOKEN = "f".repeat(64);
      process.env.OPENCLAW_GATEWAY_TOKEN = "f".repeat(64);
      serve({
        "config.yaml": "gateway:\n  token: literal-master\n  token_env: DEFENSECLAW_GATEWAY_TOKEN\n",
        ".env": "DEFENSECLAW_GATEWAY_TOKEN=" + "f".repeat(64) + "\nOPENCLAW_GATEWAY_TOKEN=x\n",
      });
      expect(loadSidecarConfig().token).toBe("");
    });

    it("refuses a credential that is not a 64-character hex token", () => {
      serve({ "config.yaml": "", ".hook-openclaw.token": "not-a-token\n" });
      expect(loadSidecarConfig().token).toBe("");
    });

    it("picks up a rotated credential without a restart (GAP-2286)", () => {
      let token = TOKEN;
      let mtime = 1000;
      serve({ "config.yaml": "gateway:\n  api_port: 18970\n" });
      mockReadFileSync.mockImplementation((path) => {
        const p = String(path);
        if (p.endsWith("config.yaml")) return "gateway:\n  api_port: 18970\n";
        if (p.endsWith(".hook-openclaw.token")) return token;
        throw new Error("ENOENT: " + p);
      });
      mockStatSync.mockImplementation((path) => {
        const p = String(path);
        return (p.endsWith(".hook-openclaw.token")
          ? { mtimeMs: mtime, size: token.length }
          : { mtimeMs: 1, size: 25 }) as ReturnType<typeof statSync>;
      });
      expect(loadSidecarConfig().token).toBe(TOKEN);
      expect(loadSidecarConfig().token).toBe(TOKEN);
      token = "1".repeat(64);
      mtime = 2000;
      expect(loadSidecarConfig().token).toBe("1".repeat(64));
    });
  });
});

describe("separate-user layout", () => {
  afterEach(() => {
    configureSidecarConnection(undefined);
    setRuntimeSettings(undefined);
    mockReadFileSync.mockReset();
  });

  it("takes the address and credential from the plugin config, never config.yaml", () => {
    mockReadFileSync.mockImplementation((path) => {
      const p = String(path);
      if (p === "/etc/defenseclaw/openclaw-plugin.token") return "c".repeat(64) + "\n";
      throw new Error("must not read " + p);
    });
    configureSidecarConnection({
      tokenFile: "/etc/defenseclaw/openclaw-plugin.token",
      sidecarHost: "127.0.0.1",
      sidecarPort: 18990,
      guardrailPort: 4010,
    });
    expect(separateUserLayout()).toBe(true);
    const cfg = loadSidecarConfig();
    expect(cfg.baseUrl).toBe("http://127.0.0.1:18990");
    expect(cfg.guardrailPort).toBe(4010);
    expect(cfg.token).toBe("c".repeat(64));
    expect(cfg.hiltEnabled).toBe(false);
  });

  it("applies the approval settings the gateway reports", () => {
    mockReadFileSync.mockImplementation(() => "c".repeat(64));
    configureSidecarConnection({ tokenFile: "/etc/defenseclaw/openclaw-plugin.token" });
    setRuntimeSettings({ hilt_enabled: true, approval_timeout_s: 90 });
    const cfg = loadSidecarConfig();
    expect(cfg.hiltEnabled).toBe(true);
    expect(cfg.approvalTimeoutS).toBe(90);
  });

  it("ignores a relative tokenFile", () => {
    configureSidecarConnection({ tokenFile: "relative/token" });
    expect(separateUserLayout()).toBe(false);
  });
});
