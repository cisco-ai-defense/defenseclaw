import { describe, it, expect } from "vitest";
import { compareSeverity, maxSeverity } from "../types.js";
import type { Severity } from "../types.js";

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
