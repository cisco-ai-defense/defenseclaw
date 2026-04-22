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

import { describe, it, expect } from "vitest";
import { compareSeverity, maxSeverity } from "../types.js";
import type { CorrelationContext, Severity } from "../types.js";

describe("compareSeverity", () => {
  it("returns 0 for equal severities", () => {
    const severities: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
    for (const s of severities) {
      expect(compareSeverity(s, s)).toBe(0);
    }
  });

  it("returns positive when first is more severe", () => {
    expect(compareSeverity("CRITICAL", "HIGH")).toBeGreaterThan(0);
    expect(compareSeverity("HIGH", "MEDIUM")).toBeGreaterThan(0);
    expect(compareSeverity("MEDIUM", "LOW")).toBeGreaterThan(0);
    expect(compareSeverity("LOW", "INFO")).toBeGreaterThan(0);
    expect(compareSeverity("CRITICAL", "INFO")).toBeGreaterThan(0);
  });

  it("returns negative when first is less severe", () => {
    expect(compareSeverity("INFO", "CRITICAL")).toBeLessThan(0);
    expect(compareSeverity("LOW", "HIGH")).toBeLessThan(0);
    expect(compareSeverity("MEDIUM", "CRITICAL")).toBeLessThan(0);
  });

  it("maintains transitivity", () => {
    expect(compareSeverity("CRITICAL", "MEDIUM")).toBeGreaterThan(
      compareSeverity("HIGH", "MEDIUM"),
    );
  });
});

describe("maxSeverity", () => {
  it("returns INFO for empty array", () => {
    expect(maxSeverity([])).toBe("INFO");
  });

  it("returns the single element for length-1 array", () => {
    expect(maxSeverity(["CRITICAL"])).toBe("CRITICAL");
    expect(maxSeverity(["LOW"])).toBe("LOW");
  });

  it("returns CRITICAL when present", () => {
    expect(maxSeverity(["LOW", "MEDIUM", "CRITICAL", "HIGH"])).toBe("CRITICAL");
  });

  it("returns HIGH when no CRITICAL", () => {
    expect(maxSeverity(["LOW", "HIGH", "MEDIUM", "INFO"])).toBe("HIGH");
  });

  it("returns MEDIUM when max is MEDIUM", () => {
    expect(maxSeverity(["LOW", "INFO", "MEDIUM"])).toBe("MEDIUM");
  });

  it("returns LOW when max is LOW", () => {
    expect(maxSeverity(["INFO", "LOW", "INFO"])).toBe("LOW");
  });

  it("returns INFO when all are INFO", () => {
    expect(maxSeverity(["INFO", "INFO", "INFO"])).toBe("INFO");
  });

  it("handles duplicates correctly", () => {
    expect(maxSeverity(["HIGH", "HIGH", "HIGH"])).toBe("HIGH");
  });
});

describe("CorrelationContext", () => {
  it("accepts the documented shape", () => {
    const ctx: CorrelationContext = {
      agentId: "a1",
      runId: "r1",
      sessionId: "s1",
      agentInstanceId: "i1",
      sidecarInstanceId: "sc1",
      traceId: "t1",
      agentName: "n1",
      policyId: "p1",
    };
    expect(ctx.agentId).toBe("a1");
  });
});
