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
import { INSPECT_BODY_BUDGET_BYTES, fitInspectBody } from "../inspect-body-limit.js";

const GATEWAY_BODY_LIMIT = 1 << 20;
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
    expect(kept).toContain("characters not sent");
  });

  it("sends a note for a call too large to cut", () => {
    const args = { items: Array.from({ length: 200_000 }, (_, i) => `value-${i}-${"y".repeat(8)}`) };
    const got = fitInspectBody({ tool: "message", args });
    expect(got.partial).toBe(true);
    expect(bodyBytes(got.payload)).toBeLessThan(INSPECT_BODY_BUDGET_BYTES);
    expect(got.payload.args_partial).toBe(true);
  });
});
