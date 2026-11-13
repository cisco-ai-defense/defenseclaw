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

import { describe, expect, it } from "vitest";
import { MESSAGE_TEXT_MAX_CHARS, extractMessageText } from "../message-text.js";

// The message tool's text can sit in any string field of its params (GAP-0177).
describe("extractMessageText", () => {
  it.each([
    ["content", { content: "one" }, "one"],
    ["body", { body: "two" }, "two"],
    ["text", { text: "three" }, "three"],
    ["message", { message: "four" }, "four"],
    ["caption", { media: "x", caption: "five" }, "five\nx"],
    ["known keys first, then the rest sorted", { zz: "last", aa: "mid", content: "first" }, "first\nmid\nlast"],
    [
      "nested blocks and attachments",
      {
        blocks: [{ type: "text", text: "b1" }, { type: "text", text: "b2" }],
        attachments: [{ title: "a1" }],
      },
      "b1\nb2\na1",
    ],
    ["routing keys are not text", { action: "send", channel: "sms", to: "+15551230000", accountId: "acct" }, ""],
    ["routing keys inside blocks are not text", { blocks: [{ type: "text", id: "blk", text: "hello" }] }, "hello"],
    ["blank strings are not text", { text: "   ", body: "" }, ""],
    ["non-string values are not text", { text: 42, flag: true, n: null, items: [1, 2] }, ""],
    ["empty params", {}, ""],
    ["no params", undefined, ""],
    ["a bare string", "hello", "hello"],
  ])("%s", (_name, params, want) => {
    expect(extractMessageText(params)).toBe(want);
  });

  it("stops below the depth limit", () => {
    let deep: unknown = "deep";
    for (let i = 0; i < 12; i++) deep = { x: deep };
    expect(extractMessageText(deep)).toBe("");
    expect(extractMessageText({ a: { b: { c: "seen" } } })).toBe("seen");
  });

  it("reads at most 512 strings", () => {
    const blocks = Array.from({ length: 562 }, () => "s");
    expect(extractMessageText({ blocks }).split("\n")).toHaveLength(512);
  });

  it("keeps the head and the tail of an oversized text", () => {
    const long = "a".repeat(MESSAGE_TEXT_MAX_CHARS) + "m".repeat(1000) + "z".repeat(MESSAGE_TEXT_MAX_CHARS);
    const out = extractMessageText({ text: long, body: long });
    expect(out.length).toBeLessThanOrEqual(MESSAGE_TEXT_MAX_CHARS + 1);
    expect(out.startsWith("a")).toBe(true);
    expect(out.endsWith("z")).toBe(true);
  });

  it("survives a cyclic params object", () => {
    const params: Record<string, unknown> = { text: "loop" };
    params.self = params;
    expect(extractMessageText(params)).toBe("loop\nloop\nloop\nloop\nloop\nloop\nloop\nloop\nloop");
  });
});
