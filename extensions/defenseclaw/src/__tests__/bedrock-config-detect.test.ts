/**
 * Copyright 2026 Cisco Systems, Inc. and its affiliates
 *
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, it, expect } from "vitest";
import { openClawConfigUsesAmazonBedrock } from "../bedrock-config-detect.js";

describe("openClawConfigUsesAmazonBedrock", () => {
  it("returns false for unrelated config", () => {
    expect(
      openClawConfigUsesAmazonBedrock({
        agents: { defaults: { model: { primary: "openai/gpt-4o" } } },
      }),
    ).toBe(false);
  });

  it("detects primary model ref amazon-bedrock/…", () => {
    expect(
      openClawConfigUsesAmazonBedrock({
        agents: {
          defaults: {
            model: { primary: "amazon-bedrock/global.amazon.nova-2-lite-v1:0" },
          },
        },
      }),
    ).toBe(true);
  });

  it("detects models.providers.amazon-bedrock", () => {
    expect(
      openClawConfigUsesAmazonBedrock({
        models: {
          providers: {
            "amazon-bedrock": {
              baseUrl: "https://bedrock-runtime.us-east-1.amazonaws.com",
              api: "bedrock-converse-stream",
            },
          },
        },
      }),
    ).toBe(true);
  });

  it("detects bedrock-runtime in baseUrl", () => {
    expect(
      openClawConfigUsesAmazonBedrock({
        models: {
          providers: {
            custom: {
              baseUrl: "https://bedrock-runtime.us-west-2.amazonaws.com",
            },
          },
        },
      }),
    ).toBe(true);
  });
});
