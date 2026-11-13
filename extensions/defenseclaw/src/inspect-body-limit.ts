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
/** Cut strings never go below this (characters). */
const MIN_CUT_CHARS = 128;
/** Room for the "not sent" marker inside a cut string (characters). */
const MARKER_CHARS = 64;
/** Share of the room left for the strings that the cut aims at, for the JSON escapes it cannot foresee. */
const CUT_SAFETY = 0.95;
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

/** A string of at most `limit` characters: its head and its tail around a marker. */
function cutString(value: string, limit: number): string {
  const keep = Math.max(16, (limit - MARKER_CHARS) >> 1);
  return `${value.slice(0, keep)}\n[... ${value.length - 2 * keep} not sent ...]\n${value.slice(-keep)}`;
}

const BASE64_ALL = /^[A-Za-z0-9+/_=\r\n-]*$/;

/** True for a long base64 value, bare or behind a base64 data URL header. */
function isBase64Payload(value: string): boolean {
  let payload = value;
  if (value.startsWith("data:")) {
    const i = value.slice(0, 256).indexOf(";base64,");
    if (i < 0) return false;
    payload = value.slice(i + ";base64,".length);
  }
  return BASE64_ALL.test(payload);
}

/**
 * Returns the payload to send. `args` and `content` are the fields that carry
 * the call; the payload is copied before it is cut.
 *
 * Only a message call is cut: any other tool keeps the answer an oversize call
 * has always had (the gateway refuses it and the check fails closed), as the
 * shell hooks do. The work is bounded and every string is cut at most once: the
 * attachments are replaced by their descriptors, then every long string is cut
 * once to its share of the room left (proportional to its length), and a call
 * that still does not fit is sent as a note.
 */
export function fitInspectBody(payload: Record<string, unknown>, budget = INSPECT_BODY_BUDGET_BYTES): FittedPayload {
  if (payload.tool !== "message" || size(payload) <= budget) return { payload, partial: false };
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
  // First the attachments: their bytes are no text anyone reads. A value in an
  // attachment field that is not base64 is text and is cut like any other.
  for (const slot of slots) {
    const value = read(slot);
    if (
      typeof slot.key === "string" && ATTACHMENT_KEYS.has(slot.key.toLowerCase()) &&
      value.length >= ATTACHMENT_MIN_CHARS && isBase64Payload(value)
    ) {
      write(slot, describeAttachment(value));
    }
  }
  // Then every string over the minimum is cut once, to its share of the room
  // left: its share of the bytes the strings take now, scaled to what fits.
  if (size(out) > budget) {
    const cuttable = slots.filter((s) => s.length > MIN_CUT_CHARS);
    const bytes = cuttable.map((s) => Buffer.byteLength(JSON.stringify(read(s))));
    const total = bytes.reduce((a, b) => a + b, 0);
    const room = budget - (size(out) - total);
    if (room > 0 && total > 0) {
      const ratio = Math.min(1, (room / total) * CUT_SAFETY);
      for (const slot of cuttable) {
        const limit = Math.max(MIN_CUT_CHARS, Math.floor(slot.length * ratio));
        if (limit < slot.length) write(slot, cutString(read(slot), limit));
      }
    }
  }
  // A call that still does not fit (a huge number of small values) is sent as
  // a note: nothing of it is read, and the gateway judges it as unknown.
  if (size(out) > budget) {
    out.args = { note: "call too large to send" };
    delete out.content;
  }
  out.args_partial = true;
  return { payload: out, partial: true };
}
