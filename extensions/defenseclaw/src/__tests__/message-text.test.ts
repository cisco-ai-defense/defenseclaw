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
import { MESSAGE_TEXT_MAX_BYTES, extractMessage } from "../message-text.js";

interface ParityCase {
  name: string;
  params?: unknown;
  gen?: Record<string, number>;
  text?: string;
  text_len?: number;
  over_cap?: boolean;
  routing?: Record<string, string>;
  head?: string;
  tail?: string;
  valid_utf8?: boolean;
}

// The cases the gateway runs too (internal/gateway/message_text_test.go): the
// plugin and the gateway read a message call's params the same way (GAP-0177,
// GAP-0290..0292).
const fixture = JSON.parse(
  readFileSync(new URL("../../../../internal/gateway/testdata/message_text_parity.json", import.meta.url), "utf8"),
) as { cases: ParityCase[] };

function paramsOf(c: ParityCase): unknown {
  const gen = c.gen ?? {};
  if (gen.leaves) return { blocks: Array.from({ length: gen.leaves }, () => "s") };
  if (gen.depth || gen.depth_empty) {
    let v: unknown = gen.depth ? "deep" : [];
    for (let i = 0; i < (gen.depth ?? gen.depth_empty); i++) v = { x: v };
    return v;
  }
  if (gen.nodes) return { items: [...Array.from({ length: gen.nodes }, () => ({})), "late"] };
  if (gen.multibyte) return { text: "é".repeat(gen.multibyte) };
  if (gen.pad) return { body: "a".repeat(gen.pad), text: "z".repeat(gen.pad) };
  return c.params;
}

describe("extractMessage", () => {
  it("has the gateway's limits", () => {
    expect(MESSAGE_TEXT_MAX_BYTES).toBe(256 * 1024);
  });

  it.each(fixture.cases.map((c) => [c.name, c] as const))("%s", (_name, c) => {
    const got = extractMessage(paramsOf(c));
    if (c.text !== undefined) expect(got.text).toBe(c.text);
    if (c.text_len !== undefined) expect(new TextEncoder().encode(got.text).length).toBe(c.text_len);
    if (c.valid_utf8) expect(got.text).not.toContain("\uFFFD");
    if (c.head) expect(got.text.startsWith(c.head)).toBe(true);
    if (c.tail) expect(got.text.endsWith(c.tail)).toBe(true);
    expect(got.overCap).toBe(c.over_cap ?? false);
    expect(got.routing).toEqual(c.routing ?? {});
  });

  it("reads no params", () => {
    expect(extractMessage(undefined)).toEqual({ text: "", overCap: false, routing: {} });
  });

  it("survives a cyclic params object", () => {
    const params: Record<string, unknown> = { text: "loop" };
    params.self = params;
    const got = extractMessage(params);
    expect(got.text.startsWith("loop\nloop")).toBe(true);
    expect(got.overCap).toBe(true);
  });
});
