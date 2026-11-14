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
import { GATEWAY_BODY_LIMIT_BYTES, INSPECT_BODY_BUDGET_BYTES, fitInspectBody } from "../inspect-body-limit.js";

const limits = JSON.parse(
  readFileSync(new URL("../../../../schemas/inspect-tool-request-limits.json", import.meta.url), "utf8"),
) as { body_max_bytes: number; plugin_envelope_margin_bytes: number };
const GATEWAY_BODY_LIMIT = limits.body_max_bytes;
const bodyBytes = (v: unknown) => Buffer.byteLength(JSON.stringify(v));
const KEY = "sk-ant-api03-" + "A7b9C2d4E6f8G1h3J5k7L9m2";

// GAP-0356: an attachment over about 770 KB made the inspect request exceed the
// gateway's 1 MiB body limit, and the call was blocked as a failed check.
// GAP-0402, GAP-0436: a call the gateway reads whole is sent whole, and a cut is
// as small as the call needs.
describe("fitInspectBody", () => {
  it("has one source for the limit: the file the gateway embeds", () => {
    expect(INSPECT_BODY_BUDGET_BYTES).toBe(GATEWAY_BODY_LIMIT - limits.plugin_envelope_margin_bytes);
    expect(limits.plugin_envelope_margin_bytes).toBeGreaterThan(0);
    expect(limits.plugin_envelope_margin_bytes).toBeLessThan(GATEWAY_BODY_LIMIT / 100);
  });

  it("sends a call that fits as it is, up to the gateway's limit", () => {
    const text = "x".repeat(INSPECT_BODY_BUDGET_BYTES - 400);
    const payload = { tool: "message", args: { message: text }, direction: "outbound" };
    expect(bodyBytes(payload)).toBeLessThanOrEqual(INSPECT_BODY_BUDGET_BYTES);
    const got = fitInspectBody(payload);
    expect(got.partial).toBe(false);
    expect(got.payload).toBe(payload);
    expect(got.payload).not.toHaveProperty("args_partial");
  });

  it.each([1, 4, 16])("replaces the bytes of a %i MB attachment with its size, type and hash", (mb) => {
    const data = `data:image/png;base64,${"AAEC".repeat((mb << 20) / 4)}`;
    const payload = { tool: "message", args: { message: "here is the photo", buffer: data, filename: "a.png" }, direction: "outbound" };
    const got = fitInspectBody(payload);
    expect(got.partial).toBe(true);
    expect(got.payload.args_partial).toBe(true);
    expect(bodyBytes(got.payload)).toBeLessThanOrEqual(INSPECT_BODY_BUDGET_BYTES);
    const args = got.payload.args as Record<string, string>;
    expect(args.message).toBe("here is the photo");
    expect(args.buffer).toMatch(/^\[attachment bytes not sent: \d+ characters, image\/png, sha256 [0-9a-f]{64}\]$/);
    // The caller's own call is not changed.
    expect((payload.args as Record<string, string>).buffer).toBe(data);
  });

  it("cuts only the longest strings, as little as the call needs (GAP-0436)", () => {
    // A call 500 bytes over the gateway limit: only the longest string is cut, by what is needed.
    const long = `${"w ".repeat(60_000)}${KEY}${" w".repeat(60_000)}`;
    const base = bodyBytes({ tool: "message", args: { message: long, caption: "" }, direction: "outbound" });
    const text = "y".repeat(GATEWAY_BODY_LIMIT - base + 500);
    const payload = { tool: "message", args: { message: long, caption: text }, direction: "outbound" };
    expect(bodyBytes(payload)).toBe(GATEWAY_BODY_LIMIT + 500);
    const got = fitInspectBody(payload);
    expect(got.partial).toBe(true);
    expect(bodyBytes(got.payload)).toBeLessThanOrEqual(INSPECT_BODY_BUDGET_BYTES);
    const args = got.payload.args as Record<string, string>;
    // The string that holds the key is shorter than the filler and is left whole.
    expect(args.message).toBe(long);
    expect(args.message).toContain(KEY);
    expect(args.caption.length).toBeGreaterThan(text.length - 5000);
  });

  it("keeps the head and the tail of a very long text", () => {
    const text = `HEAD${"x".repeat(3 << 20)}TAIL`;
    const got = fitInspectBody({ tool: "message", args: { text } });
    expect(got.partial).toBe(true);
    expect(bodyBytes(got.payload)).toBeLessThanOrEqual(INSPECT_BODY_BUDGET_BYTES);
    const kept = (got.payload.args as Record<string, string>).text;
    expect(kept.startsWith("HEAD")).toBe(true);
    expect(kept.endsWith("TAIL")).toBe(true);
    expect(kept).toMatch(/\[\.\.\. \d+ not sent \.\.\.\]/);
  });

  it.each([
    ["24 x 50,000", 24, 50_000],
    ["30 x 40,000", 30, 40_000],
    ["60 x 33,000", 60, 33_000],
    ["500 x 40,000", 500, 40_000],
    ["1000 x 32 KiB", 1000, 32 * 1024],
  ])("fits %s characters of filler in bounded time (GAP-0361)", (_name, count, chars) => {
    const args = Object.fromEntries(Array.from({ length: count }, (_, i) => [`f${i}`, "x".repeat(chars)]));
    const start = performance.now();
    const got = fitInspectBody({ tool: "message", args });
    expect(performance.now() - start).toBeLessThan(3000);
    expect(got.partial).toBe(true);
    expect(got.payload.args_partial).toBe(true);
    expect(bodyBytes(got.payload)).toBeLessThanOrEqual(INSPECT_BODY_BUDGET_BYTES);
  });

  it("fits a 16 MB attachment next to many long strings in bounded time", () => {
    const args: Record<string, unknown> = { buffer: `data:image/png;base64,${"AAEC".repeat((16 << 20) / 4)}` };
    for (let i = 0; i < 1000; i++) args[`field${i}`] = `${i}:${"z".repeat(32 * 1024)}`;
    const start = performance.now();
    const got = fitInspectBody({ tool: "message", args });
    expect(performance.now() - start).toBeLessThan(5000);
    expect(got.partial).toBe(true);
    expect(bodyBytes(got.payload)).toBeLessThanOrEqual(INSPECT_BODY_BUDGET_BYTES);
  });

  // A fixed-seed fuzz: random shapes of long and short strings, nested, never
  // loop and always end under the budget.
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
    const payload = { tool: "message", args: { items: Array.from({ length: 30 + next(120) }, () => value(0)) } };
    const start = performance.now();
    const got = fitInspectBody(payload);
    expect(performance.now() - start).toBeLessThan(8000);
    expect(bodyBytes(got.payload)).toBeLessThanOrEqual(INSPECT_BODY_BUDGET_BYTES);
    expect(got.partial).toBe(bodyBytes(payload) > INSPECT_BODY_BUDGET_BYTES);
  });

  it("sends a note with the text and the recipients for a call too large to cut", () => {
    const params = {
      to: "+15550001111",
      target: { id: "u-7" },
      message: `status ${KEY}`,
      presentation: { blocks: [{ type: "table", rows: Array.from({ length: 200_000 }, (_, i) => [i, i * 7]) }] },
    };
    const payload = { tool: "message", args: params, direction: "outbound" };
    expect(bodyBytes(payload)).toBeGreaterThan(GATEWAY_BODY_LIMIT);
    const got = fitInspectBody(payload);
    expect(got.partial).toBe(true);
    expect(got.payload.args_partial).toBe(true);
    expect(bodyBytes(got.payload)).toBeLessThanOrEqual(INSPECT_BODY_BUDGET_BYTES);
    const args = got.payload.args as Record<string, unknown>;
    expect(args.to).toBe("+15550001111");
    expect(args.id).toBe("u-7");
    expect(typeof args.note).toBe("string");
    expect(args.text).toContain(KEY);
  });

  it("sends the shape of 790 KB of numbers around a key whole (rel read it whole)", () => {
    const params = {
      to: "+15550001111",
      message: `status ${KEY}`,
      presentation: { blocks: [{ type: "table", rows: Array.from({ length: 56_000 }, (_, i) => [i, i * 7]) }] },
    };
    const payload = { tool: "message", args: params, direction: "outbound" };
    expect(bodyBytes(payload)).toBeGreaterThan(700 * 1024);
    expect(bodyBytes(payload)).toBeLessThanOrEqual(INSPECT_BODY_BUDGET_BYTES);
    expect(fitInspectBody(payload).payload).toBe(payload);
  });

  it("cuts only a message, whatever the case of its name: any other tool is sent whole", () => {
    const args = { command: "x".repeat(2 << 20) };
    for (const tool of ["exec", "write", "bash"]) {
      const payload = { tool, args };
      const got = fitInspectBody(payload);
      expect(got.partial).toBe(false);
      expect(got.payload).toBe(payload);
    }
    const message = { message: "x".repeat(2 << 20) };
    expect(fitInspectBody({ tool: "Message", args: message }).partial).toBe(true);
    expect(fitInspectBody({ tool: "MESSAGE", args: message }).partial).toBe(true);
    expect(fitInspectBody({ tool: "messages", args: message }).partial).toBe(false);
  });

  it("describes only a line-wrapped base64 attachment: a value with spaces or other text is cut as text", () => {
    const wrapped = `${"QUJD".repeat(2000)}=\n${"QUJD".repeat(2000)}-_\r\n${"QUJD".repeat(2000)}`;
    const described = fitInspectBody({ tool: "message", args: { buffer: wrapped + "x".repeat(1_200_000) } });
    expect((described.payload.args as Record<string, string>).buffer).toMatch(/^\[attachment bytes not sent/);
    const spaced = fitInspectBody({ tool: "message", args: { buffer: `${wrapped} ${"x".repeat(1_200_000)}` } });
    expect((spaced.payload.args as Record<string, string>).buffer).not.toMatch(/^\[attachment bytes not sent/);
    expect(spaced.partial).toBe(true);
    const words = fitInspectBody({ tool: "message", args: { buffer: "word ".repeat(300_000), message: "hi" } });
    const buffer = (words.payload.args as Record<string, string>).buffer;
    expect(buffer.startsWith("word word")).toBe(true);
    expect(buffer).toContain("not sent");
    expect(buffer).not.toContain("attachment bytes not sent");
  });
});

// GAP-0436, round 5: a call whose body is over the cut target by a few bytes but
// under the gateway's limit is sent whole: rel read these calls whole (its body
// is the params plus a copy of the text) and blocked the key in them. The shapes
// are the review's band shapes; the Go side (TestInspectToolMessageMarginBandStillBlocksTheKey)
// builds the same bytes and reads them through the gateway.
describe("fitInspectBody margin band (GAP-0436)", () => {
  const prose = (n: number) => "the quarterly plan is attached for review. ".repeat(Math.ceil(n / 43) + 1).slice(0, n);
  const keyText = `${prose(7000)} key: ${KEY} ${prose(7000)}`;
  const wrap = (params: Record<string, unknown>) => ({ tool: "message", args: params, direction: "outbound", approval_surface: "native" });
  const rows = (n: number) => Array.from({ length: n }, (_, r) => Array.from({ length: 10 }, (_, c) => r * 10 + c));

  // The call whose JSON is exactly `target` bytes: `coarse(n)` grows with n; a list of small numbers fills the rest.
  const exact = (target: number, coarse: (n: number) => Record<string, unknown>, most: number): Record<string, unknown> => {
    const sized = (n: number, pad: number[]) => bodyBytes(wrap({ ...coarse(n), pad }));
    let lo = 0;
    let hi = most;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (sized(mid, []) <= target - 4) lo = mid;
      else hi = mid - 1;
    }
    let count = 0;
    let top = target;
    while (count < top) {
      const mid = (count + top + 1) >> 1;
      if (sized(lo, new Array<number>(mid).fill(0)) <= target) count = mid;
      else top = mid - 1;
    }
    const pad = new Array<number>(count).fill(0);
    for (let i = 0; i < target - sized(lo, pad); i++) pad[i] = 10;
    expect(sized(lo, pad)).toBe(target);
    return { ...coarse(lo), pad };
  };

  const shapes: Array<[string, number, number, (n: number) => Record<string, unknown>]> = [
    ["band-body-numtable-1b", 1, 30_000, (n) => ({ action: "send", to: "+15550001111", body: keyText, presentation: { blocks: [{ type: "table", rows: rows(n) }] } })],
    ["band-body-numtable", 100, 30_000, (n) => ({ action: "send", to: "+15550001111", body: keyText, presentation: { blocks: [{ type: "table", rows: rows(n) }] } })],
    ["band-content-numtable", 100, 30_000, (n) => ({ action: "send", to: "+15550001111", content: keyText, presentation: { blocks: [{ type: "table", rows: rows(n) }] } })],
    ["band-body-short", 200, 20_000, (n) => ({ action: "send", to: "+15550001111", body: keyText, notes: Array.from({ length: n }, () => "y".repeat(100)) })],
    ["band-body-eqstrings", 150, 100, (n) => ({ action: "send", to: "+15550001111", body: keyText, ...Object.fromEntries(Array.from({ length: n }, (_, i) => [`f${i}`, "y".repeat(keyText.length)])) })],
  ];

  it.each(shapes)("%s is sent whole", (_name, over, most, coarse) => {
    const params = exact(INSPECT_BODY_BUDGET_BYTES + over, coarse, most);
    const payload = wrap(params);
    expect(bodyBytes(payload)).toBe(INSPECT_BODY_BUDGET_BYTES + over);
    expect(bodyBytes(payload)).toBeLessThanOrEqual(GATEWAY_BODY_LIMIT_BYTES);
    const got = fitInspectBody(payload);
    expect(got.partial).toBe(false);
    expect(got.payload).toBe(payload);
    expect(got.payload).not.toHaveProperty("args_partial");
  });

  it("sends a call of exactly the limit whole and cuts one byte more", () => {
    const text = "x".repeat(GATEWAY_BODY_LIMIT_BYTES - bodyBytes(wrap({ message: "" })));
    const atLimit = wrap({ message: text });
    expect(bodyBytes(atLimit)).toBe(GATEWAY_BODY_LIMIT_BYTES);
    expect(fitInspectBody(atLimit).partial).toBe(false);
    const over = wrap({ message: `${text}x` });
    const got = fitInspectBody(over);
    expect(got.partial).toBe(true);
    expect(bodyBytes(got.payload)).toBeLessThanOrEqual(INSPECT_BODY_BUDGET_BYTES);
  });
});

