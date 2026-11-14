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
import { BASE64_ALL, ROUTING_KEYS } from "./message-text.js";

/**
 * Fits a call to the gateway's request body limit (GAP-0356).
 *
 * The gateway refuses an inspect request over 1 MiB, and base64 inflates an
 * attachment past that at about 770 KB, so a photo send failed closed. A call
 * over the budget below is cut down before it is sent: an attachment's bytes
 * become its size, media type and SHA-256, and any other very long string
 * keeps its head and its tail. The request then carries `args_partial: true`:
 * the part that was not sent is unread, and the gateway judges the call at
 * least at the unknown tier of its policy (alert in the default and permissive
 * packs, block in strict). A call that fits is sent as it is.
 *
 * Decision (lead, GAP-0356): a message over the limit gets the unknown tier of
 * the pack, not a block in every pack. Any other tool is never cut here: the
 * gateway refuses it, as it always has, and the check fails closed.
 */

/** The gateway's request body limit for /api/v1/inspect/tool (apiRequestBodyMaxBytes). */
export const GATEWAY_BODY_LIMIT_BYTES = 1 << 20;
/** What the request carries beyond the call: its envelope fields and the flag. */
export const ENVELOPE_MARGIN_BYTES = 8 * 1024;
/**
 * The body a call may take and still be sent as it is: the gateway's limit
 * less the margin. A call the gateway reads whole is sent whole
 * (rel-1-0-10:GAP-0402). schemas/inspect-tool-request-limits.json holds both
 * numbers for the tests of the two sides.
 */
export const INSPECT_BODY_BUDGET_BYTES = GATEWAY_BODY_LIMIT_BYTES - ENVELOPE_MARGIN_BYTES;
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

/** Keeps the routing values of a call (the recipient, target, channel ...): strings and lists of strings. */
function collectRouting(args: unknown): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  let nodes = 0;
  let bytes = 0;
  const visit = (value: unknown, depth: number): void => {
    if (value === null || typeof value !== "object" || depth > 8 || nodes++ > 4096) return;
    if (Array.isArray(value)) {
      for (const item of value) visit(item, depth + 1);
      return;
    }
    for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
      if (ROUTING_KEYS.has(key.toLowerCase())) {
        const keep =
          typeof item === "string" ? item.slice(0, 4096)
            : Array.isArray(item) && item.every((i) => typeof i === "string") ? (item as string[]).slice(0, 64).map((i) => i.slice(0, 4096))
              : undefined;
        if (keep !== undefined && bytes < 64 * 1024) {
          bytes += JSON.stringify(keep).length;
          let name = key;
          for (let n = 2; name in out; n++) name = `${key}#${n}`;
          out[name] = keep;
        }
      } else {
        visit(item, depth + 1);
      }
    }
  };
  visit(args, 0);
  return out;
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
  if (String(payload.tool).toLowerCase() !== "message" || size(payload) <= budget) return { payload, partial: false };
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
  // A call that still does not fit (numbers and short values past the cut)
  // keeps what is read: the message text (the plugin's own reading of it, cut
  // to the room left, head and tail) and the routing values. Only the
  // attachments and the rest of the structure are dropped. The gateway judges
  // the call as unknown on top of what it reads.
  if (size(out) > budget) {
    const content = typeof payload.content === "string" ? payload.content : "";
    out.args = { ...collectRouting(payload.args), note: "call too large to send: attachments and the rest of the structure are not sent" };
    delete out.content;
    const room = budget - size(out) - 1024;
    if (content !== "" && room > MIN_CUT_CHARS) {
      const bytesPerChar = Math.max(1, Buffer.byteLength(JSON.stringify(content)) / content.length);
      const limit = Math.floor((room / bytesPerChar) * CUT_SAFETY);
      out.content = limit >= content.length ? content : cutString(content, Math.max(limit, MIN_CUT_CHARS));
      if (size(out) > budget) delete out.content;
    }
  }
  out.args_partial = true;
  return { payload: out, partial: true };
}
