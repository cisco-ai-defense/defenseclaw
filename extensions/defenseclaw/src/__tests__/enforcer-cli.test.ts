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

import { beforeEach, describe, expect, it, vi } from "vitest";

const { mockExecFile } = vi.hoisted(() => ({
  mockExecFile: vi.fn(),
}));

vi.mock("node:child_process", () => ({
  execFile: mockExecFile,
}));

import { runPluginScan } from "../policy/enforcer.js";

describe("runPluginScan", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("invokes the defenseclaw CLI with plugin subcommands", async () => {
    mockExecFile.mockImplementation((_cmd, _args, _opts, cb) => {
      cb(null, JSON.stringify({ findings: [] }), "");
    });

    const result = await runPluginScan("/plugins/test");

    expect(result.findings).toEqual([]);
    expect(mockExecFile).toHaveBeenCalledWith(
      "defenseclaw",
      ["plugin", "scan", "/plugins/test", "--json"],
      expect.any(Object),
      expect.any(Function),
    );
  });

  it("surfaces non-zero exits without stdout", async () => {
    mockExecFile.mockImplementation((_cmd, _args, _opts, cb) => {
      cb({ code: 127 }, "", "not found");
    });

    await expect(runPluginScan("/plugins/test")).rejects.toThrow(
      "defenseclaw plugin scan exited 127: not found",
    );
  });

  it("fails when stdout is not valid JSON", async () => {
    mockExecFile.mockImplementation((_cmd, _args, _opts, cb) => {
      cb(null, "not-json", "");
    });

    await expect(runPluginScan("/plugins/test")).rejects.toThrow(
      "failed to parse plugin scan output",
    );
  });
});
