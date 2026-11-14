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

import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  ENVELOPE_MARGIN_BYTES,
  GATEWAY_BODY_LIMIT_BYTES as GATEWAY_LIMIT,
  INSPECT_BODY_BUDGET_BYTES,
  fitInspectBody,
} from "../inspect-body-limit.js";
import { extractMessage } from "../message-text.js";

const GATEWAY_BODY_LIMIT = GATEWAY_LIMIT;
const bodyBytes = (v: unknown) => Buffer.byteLength(JSON.stringify(v));

// GAP-0356: an attachment over about 770 KB made the inspect request exceed the
// gateway's 1 MiB body limit, and the call was blocked as a failed check.
describe("fitInspectBody", () => {
  it("sends a call that fits as it is", () => {
    const payload = { tool: "message", args: { message: "hi", buffer: "QUJD".repeat(1000) }, content: "hi" };
    const got = fitInspectBody(payload);
    expect(got.partial).toBe(false);
    expect(got.payload).toBe(payload);
    expect(got.payload).not.toHaveProperty("args_partial");
  });

  it.each([1, 4, 16])("replaces the bytes of a %i MB attachment with its size, type and hash", (mb) => {
    const data = `data:image/png;base64,${"AAEC".repeat((mb << 20) / 4)}`;
    const payload = { tool: "message", args: { message: "here is the photo", buffer: data, filename: "a.png" }, content: "here is the photo", direction: "outbound" };
    const got = fitInspectBody(payload);
    expect(got.partial).toBe(true);
    expect(got.payload.args_partial).toBe(true);
    expect(bodyBytes(got.payload)).toBeLessThan(INSPECT_BODY_BUDGET_BYTES);
    expect(bodyBytes(got.payload)).toBeLessThan(GATEWAY_BODY_LIMIT);
    const args = got.payload.args as Record<string, string>;
    expect(args.message).toBe("here is the photo");
    expect(args.buffer).toMatch(/^\[attachment bytes not sent: \d+ characters, image\/png, sha256 [0-9a-f]{64}\]$/);
    // The caller's own call is not changed.
    expect((payload.args as Record<string, string>).buffer).toBe(data);
  });

  it("keeps the head and the tail of a very long text", () => {
    const text = `HEAD${"x".repeat(2 << 20)}TAIL`;
    const got = fitInspectBody({ tool: "message", args: { text }, content: text });
    expect(got.partial).toBe(true);
    expect(bodyBytes(got.payload)).toBeLessThan(INSPECT_BODY_BUDGET_BYTES);
    const kept = (got.payload.args as Record<string, string>).text;
    expect(kept.startsWith("HEAD")).toBe(true);
    expect(kept.endsWith("TAIL")).toBe(true);
    expect(kept).toMatch(/\[\.\.\. \d+ not sent \.\.\.\]/);
  });

  it("fits 1000 values of 32 KiB and a 16 MB attachment in bounded time (GAP-0361)", () => {
    const args: Record<string, unknown> = { buffer: `data:image/png;base64,${"AAEC".repeat((16 << 20) / 4)}` };
    for (let i = 0; i < 1000; i++) args[`field${i}`] = `${i}:${"z".repeat(32 * 1024)}`;
    const start = performance.now();
    const got = fitInspectBody({ tool: "message", args, content: "hi" });
    expect(performance.now() - start).toBeLessThan(5000);
    expect(got.partial).toBe(true);
    expect(got.payload.args_partial).toBe(true);
    expect(bodyBytes(got.payload)).toBeLessThan(INSPECT_BODY_BUDGET_BYTES);
  });

  // A fixed-seed fuzz: random shapes of long and short strings, nested, never
  // loop and always end under the budget or as a note.
  it.each([1, 2, 3, 5, 8, 13, 21, 34, 55, 89])("terminates and fits for fuzz seed %i", (seed) => {
    let state = seed * 2654435761 >>> 0;
    const next = (n: number) => {
      state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
      return state % n;
    };
    const value = (depth: number): unknown => {
      const kind = next(depth > 3 ? 2 : 4);
      if (kind === 0) return "s".repeat(next(4) === 0 ? 1000 + next(100_000) : next(200));
      if (kind === 1) return next(1000);
      if (kind === 2) return Array.from({ length: next(40) }, () => value(depth + 1));
      return Object.fromEntries(Array.from({ length: next(40) }, (_, i) => [`k${i}`, value(depth + 1)]));
    };
    const payload = { tool: "message", args: { items: Array.from({ length: 30 + next(120) }, () => value(0)) }, content: "x".repeat(next(3) ? 10 : 900_000) };
    const start = performance.now();
    const got = fitInspectBody(payload);
    expect(performance.now() - start).toBeLessThan(8000);
    expect(bodyBytes(got.payload)).toBeLessThan(INSPECT_BODY_BUDGET_BYTES);
    expect(got.partial).toBe(bodyBytes(payload) > INSPECT_BODY_BUDGET_BYTES);
  });

  it.each([
    ["24 x 50,000", 24, 50_000],
    ["30 x 40,000", 30, 40_000],
    ["60 x 33,000", 60, 33_000],
    ["500 x 40,000", 500, 40_000],
  ])("fits %s characters of filler in bounded time (GAP-0361)", (_name, count, chars) => {
    const args = Object.fromEntries(Array.from({ length: count }, (_, i) => [`f${i}`, "x".repeat(chars)]));
    const start = performance.now();
    const got = fitInspectBody({ tool: "message", args });
    expect(performance.now() - start).toBeLessThan(3000);
    expect(got.partial).toBe(true);
    expect(got.payload.args_partial).toBe(true);
    expect(bodyBytes(got.payload)).toBeLessThan(INSPECT_BODY_BUDGET_BYTES);
  });

  it("cuts only a message: any other tool is sent as it is and the gateway refuses it as before", () => {
    const args = { command: "x".repeat(2 << 20) };
    for (const tool of ["exec", "write", "bash"]) {
      const payload = { tool, args };
      const got = fitInspectBody(payload);
      expect(got.partial).toBe(false);
      expect(got.payload).toBe(payload);
    }
  });

  it("describes only an attachment that is base64: other text in a buffer field is cut as text", () => {
    const words = "word ".repeat(300_000);
    const got = fitInspectBody({ tool: "message", args: { buffer: words, message: "hi" } });
    const buffer = (got.payload.args as Record<string, string>).buffer;
    expect(buffer.startsWith("word word")).toBe(true);
    expect(buffer).toContain("not sent");
    expect(buffer).not.toContain("attachment bytes not sent");
  });

  it("sends a note for a call too large to cut", () => {
    const args = { items: Array.from({ length: 200_000 }, (_, i) => `value-${i}-${"y".repeat(8)}`) };
    const got = fitInspectBody({ tool: "message", args });
    expect(got.partial).toBe(true);
    expect(bodyBytes(got.payload)).toBeLessThan(INSPECT_BODY_BUDGET_BYTES);
    expect(got.payload.args_partial).toBe(true);
  });
});

// GAP-0402: the budget is the gateway's limit less a margin, from one file both
// sides check; a call rel read whole is sent whole, and one that is too large
// keeps its text and its recipients.
describe("fitInspectBody budget and note (GAP-0402)", () => {
  const limits = JSON.parse(
    readFileSync(new URL("../../../../schemas/inspect-tool-request-limits.json", import.meta.url), "utf8"),
  ) as { body_max_bytes: number; plugin_envelope_margin_bytes: number; plugin_budget_bytes: number };
  const KEY = "sk-ant-api03-" + "A7b9C2d4E6f8G1h3J5k7L9m2";

  it("takes its numbers from the shared limits file", () => {
    expect(GATEWAY_LIMIT).toBe(limits.body_max_bytes);
    expect(ENVELOPE_MARGIN_BYTES).toBe(limits.plugin_envelope_margin_bytes);
    expect(INSPECT_BODY_BUDGET_BYTES).toBe(limits.plugin_budget_bytes);
    expect(limits.plugin_budget_bytes).toBe(limits.body_max_bytes - limits.plugin_envelope_margin_bytes);
  });

  it("sends a call of 810 KB whose bulk is numbers as it is (rel read it whole)", () => {
    const params = {
      to: "+15550001111",
      message: `status ${KEY}`,
      presentation: { blocks: [{ type: "table", rows: Array.from({ length: 70_000 }, (_, i) => [i, i * 7]) }] },
    };
    const payload = { tool: "message", args: params, content: extractMessage(params).text, direction: "outbound" };
    expect(bodyBytes(payload)).toBeGreaterThan(768 * 1024);
    expect(bodyBytes(payload)).toBeLessThan(INSPECT_BODY_BUDGET_BYTES);
    const got = fitInspectBody(payload);
    expect(got.partial).toBe(false);
    expect(got.payload).toBe(payload);
  });

  it("keeps the message text and the recipients when the note is all that fits", () => {
    const params = {
      to: "+15550001111",
      target: { id: "u-7" },
      message: `status ${KEY}`,
      presentation: { blocks: [{ type: "table", rows: Array.from({ length: 160_000 }, (_, i) => [i, i * 7]) }] },
    };
    const payload = { tool: "message", args: params, content: extractMessage(params).text, direction: "outbound" };
    expect(bodyBytes(payload)).toBeGreaterThan(GATEWAY_BODY_LIMIT);
    const got = fitInspectBody(payload);
    expect(got.partial).toBe(true);
    expect(got.payload.args_partial).toBe(true);
    expect(bodyBytes(got.payload)).toBeLessThan(INSPECT_BODY_BUDGET_BYTES);
    const args = got.payload.args as Record<string, unknown>;
    expect(args.to).toBe("+15550001111");
    expect(typeof args.note).toBe("string");
    expect(got.payload.content).toContain(KEY);
  });

  it("treats the tool name case-insensitively, as the gateway does", () => {
    const args = { message: "x".repeat(2 << 20) };
    expect(fitInspectBody({ tool: "Message", args }).partial).toBe(true);
    expect(fitInspectBody({ tool: "MESSAGE", args }).partial).toBe(true);
    expect(fitInspectBody({ tool: "messages", args }).partial).toBe(false);
  });

  it("describes a line-wrapped base64 value of either alphabet; a value with spaces is cut as text", () => {
    const wrapped = `${"QUJD".repeat(2000)}=\n${"QUJD".repeat(2000)}-_\r\n${"QUJD".repeat(2000)}`;
    const described = fitInspectBody({ tool: "message", args: { buffer: wrapped + "x".repeat(1_200_000) } });
    expect((described.payload.args as Record<string, string>).buffer).toMatch(/^\[attachment bytes not sent/);
    const spaced = fitInspectBody({ tool: "message", args: { buffer: `${wrapped} ${"x".repeat(1_200_000)}` } });
    expect((spaced.payload.args as Record<string, string>).buffer).not.toMatch(/^\[attachment bytes not sent/);
    expect(spaced.partial).toBe(true);
  });
});
