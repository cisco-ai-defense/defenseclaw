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

import { createHash } from "node:crypto";

/**
 * Fits a call to the gateway's request body limit (GAP-0356).
 *
 * The gateway refuses an inspect request over 1 MiB, and base64 inflates an
 * attachment past that at about 770 KB, so a photo send failed closed. A call
 * over the budget below is cut down before it is sent: an attachment's bytes
 * become its size, media type and SHA-256, and any other very long string
 * keeps its head and its tail. The request then carries `args_partial: true`:
 * the part that was not sent is unread, and the gateway judges the call at
 * least at the unknown tier of its policy (alert in the default pack, block in
 * strict). A call that fits is sent as it is.
 */

/** Request body budget: under the gateway's 1 MiB limit, with room for the envelope. */
export const INSPECT_BODY_BUDGET_BYTES = 768 * 1024;
/** Characters of a long string kept at each end. */
const KEEP_CHARS = 16 * 1024;
/** Strings shorter than this are not worth cutting. */
const MIN_CUT_CHARS = 4 * KEEP_CHARS / 2;
/** An attachment field's value this long is replaced by its descriptor. */
const ATTACHMENT_MIN_CHARS = 4096;

const ATTACHMENT_KEYS = new Set(["buffer", "media"]);

export interface FittedPayload {
  payload: Record<string, unknown>;
  /** True when part of the call was not sent. */
  partial: boolean;
}

function size(payload: unknown): number {
  return Buffer.byteLength(JSON.stringify(payload) ?? "");
}

/** The descriptor of an attachment value: what the gateway can judge without its bytes. */
function describeAttachment(value: string): string {
  const mime = /^data:([^;,]*)[;,]/.exec(value.slice(0, 256))?.[1] || "unknown type";
  const hash = createHash("sha256").update(value).digest("hex");
  return `[attachment bytes not sent: ${value.length} characters, ${mime}, sha256 ${hash}]`;
}

interface Slot {
  container: Record<string, unknown> | unknown[];
  key: string | number;
  length: number;
}

/** Collects the long strings of a value, with where each sits. */
function collect(value: unknown, out: Slot[], seen: Set<unknown>, depth: number): void {
  if (value === null || typeof value !== "object" || seen.has(value) || depth > 64) return;
  seen.add(value);
  const container = value as Record<string, unknown> | unknown[];
  for (const key of Object.keys(container)) {
    const item = (container as Record<string, unknown>)[key];
    if (typeof item === "string") {
      out.push({ container, key: Array.isArray(container) ? Number(key) : key, length: item.length });
    } else {
      collect(item, out, seen, depth + 1);
    }
  }
}

/**
 * Returns the payload to send. `args` and `content` are the fields that carry
 * the call; the payload is copied before it is cut.
 */
export function fitInspectBody(payload: Record<string, unknown>, budget = INSPECT_BODY_BUDGET_BYTES): FittedPayload {
  if (size(payload) <= budget) return { payload, partial: false };
  const out: Record<string, unknown> = { ...payload };
  const slots: Slot[] = [];
  if (out.args !== null && typeof out.args === "object") {
    out.args = structuredClone(out.args);
    collect(out.args, slots, new Set(), 0);
  }
  if (typeof out.content === "string") slots.push({ container: out, key: "content", length: out.content.length });
  const read = (s: Slot) => (s.container as Record<string, unknown>)[s.key as string] as string;
  const write = (s: Slot, v: string) => {
    (s.container as Record<string, unknown>)[s.key as string] = v;
    s.length = v.length;
  };
  // First the attachments: their bytes are no text anyone reads.
  for (const slot of slots) {
    const value = read(slot);
    if (typeof slot.key === "string" && ATTACHMENT_KEYS.has(slot.key.toLowerCase()) && value.length >= ATTACHMENT_MIN_CHARS) {
      write(slot, describeAttachment(value));
    }
  }
  // Then the longest strings, each to its head and its tail, until the call fits.
  while (size(out) > budget) {
    const longest = slots.reduce((a, b) => (b.length > a.length ? b : a), slots[0]);
    if (!longest || longest.length < MIN_CUT_CHARS) break;
    const value = read(longest);
    write(longest, `${value.slice(0, KEEP_CHARS)}\n[... ${value.length - 2 * KEEP_CHARS} characters not sent ...]\n${value.slice(-KEEP_CHARS)}`);
  }
  // A call that still does not fit (a huge number of small values) is sent as
  // a note: nothing of it is read, and the gateway judges it as unknown.
  if (size(out) > budget) out.args = { note: "call too large to send" }, delete out.content;
  out.args_partial = true;
  return { payload: out, partial: true };
}
