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
// Copied from schemas/inspect-tool-request-limits.json by `make plugin`: the
// gateway reads its request body limit from the same file.
import limits from "./inspect-tool-request-limits.json" with { type: "json" };

/**
 * Fits a message call to the gateway's request body limit
 * (rel-1-0-10:GAP-0356, GAP-0402, GAP-0436).
 *
 * The plugin sends a message call as it is, the params and nothing else: the
 * gateway reads the text, the recipients and the attachments out of them, and
 * judges them as the rules of its pack say. It cuts a call only when it does
 * not fit the gateway's request body limit (less a small margin for the
 * envelope), and then as little as it must:
 *
 *  1. an attachment's bytes become its size, media type and SHA-256;
 *  2. the longest strings are cut to one common length (head and tail around a
 *     marker), the shorter ones are left alone, each cut at most once;
 *  3. a call that still does not fit is sent as a note: its routing values
 *     (the recipient, target, channel ...) and its strings, cut to the room.
 *
 * A cut call carries `args_partial: true`: the part that was not sent is
 * unread, and the gateway judges the call at least at the unknown tier of its
 * policy (alert in the default and permissive packs, block in strict), not a
 * block for its size. Any other tool is never cut here: the gateway refuses it
 * as it always has and the check fails closed, as the shell hooks do.
 */

/** The body a call may take and still be sent as it is, which is what the gateway reads whole. */
export const INSPECT_BODY_BUDGET_BYTES = limits.body_max_bytes - limits.plugin_envelope_margin_bytes;

/** Cut strings never go below this (characters). */
const MIN_CUT_CHARS = 128;
/** Room for the "not sent" marker inside a cut string (characters). */
const MARKER_CHARS = 64;
/**
 * Shares of the room the cut aims at, tried in turn on a fresh copy of the
 * call: the first leaves only the rounding of the JSON escapes, the others
 * allow for a call whose escapes cost more than the length suggests.
 */
const CUT_SAFETIES = [0.9995, 0.99, 0.9];
/** An attachment field's value this long is replaced by its descriptor. */
const ATTACHMENT_MIN_CHARS = 4096;

/** The fields that carry an attachment, at any depth. */
export const ATTACHMENT_KEYS = new Set(["buffer", "media"]);

/**
 * Routing and control fields: where a message goes, not what it says. The
 * gateway reads them as routing values (messageRoutingKeys).
 */
export const ROUTING_KEYS = new Set([
  "action", "channel", "provider", "accountid", "account", "to", "target",
  "targets", "from", "recipient", "recipients", "replyto", "threadid",
  "messageid", "chatid", "id", "type", "kind", "mode", "format", "parsemode",
  "silent", "dryrun", "timeoutms", "besteffort", "gatewayurl",
  "gatewaytoken",
]);

/**
 * A value of base64 characters (either alphabet) and padding, wrapped at line
 * breaks, all through. A value with a space or a tab in it is not one here: the
 * gateway reads it as text as well as decoding it (messageLenientBase64), so
 * the plugin cuts it as text.
 */
export const BASE64_ALL = /^[A-Za-z0-9+/_=\n\r\f\v-]*$/;

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

/** Collects the strings of a value, with where each sits. */
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

/** The routing values of a call (the recipient, target, channel ...): strings and lists of strings. */
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
        } else if (keep === undefined) {
          // A routing key that holds an object (a target with its own fields).
          visit(item, depth + 1);
        }
      } else {
        visit(item, depth + 1);
      }
    }
  };
  visit(args, 0);
  return out;
}

/** The strings of a call outside its routing values, in order, joined by newlines. */
function collectText(args: unknown): string {
  const parts: string[] = [];
  let nodes = 0;
  const visit = (value: unknown, depth: number): void => {
    if (nodes++ > 100_000 || depth > 64) return;
    if (typeof value === "string") {
      if (value.trim() !== "") parts.push(value);
    } else if (Array.isArray(value)) {
      for (const item of value) visit(item, depth + 1);
    } else if (value !== null && typeof value === "object") {
      for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
        if (!ROUTING_KEYS.has(key.toLowerCase())) visit(item, depth + 1);
      }
    }
  };
  visit(args, 0);
  return parts.join("\n");
}

/**
 * Cuts the longest strings to one common length so that the call fits, the
 * shorter ones untouched: the length is the largest the room allows. Returns
 * false when nothing can be cut to fit.
 */
function cutLongest(out: Record<string, unknown>, slots: Slot[], budget: number, safety: number): boolean {
  const read = (s: Slot) => (s.container as Record<string, unknown>)[s.key as string] as string;
  const cuttable = slots.filter((s) => s.length > MIN_CUT_CHARS);
  if (cuttable.length === 0) return false;
  const bytes = cuttable.map((s) => Buffer.byteLength(JSON.stringify(read(s))));
  const total = bytes.reduce((a, b) => a + b, 0);
  const room = (budget - (size(out) - total)) * safety;
  const floor = cuttable.length * (MIN_CUT_CHARS + MARKER_CHARS);
  if (room < floor) return false;
  // The largest byte length C such that every string over C is cut to C fits.
  let lo = MIN_CUT_CHARS;
  let hi = Math.max(...bytes);
  const fits = (c: number) => bytes.reduce((a, b) => a + Math.min(b, c), 0) <= room;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (fits(mid)) lo = mid;
    else hi = mid - 1;
  }
  cuttable.forEach((slot, i) => {
    if (bytes[i] > lo) {
      const limit = Math.max(MIN_CUT_CHARS, Math.floor((slot.length * lo) / bytes[i]));
      (slot.container as Record<string, unknown>)[slot.key as string] = cutString(read(slot), limit);
    }
  });
  return true;
}

/**
 * Returns the payload to send. The payload is copied before it is cut. The work
 * is bounded: one pass for the attachments, one cut, one note.
 */
export function fitInspectBody(payload: Record<string, unknown>, budget = INSPECT_BODY_BUDGET_BYTES): FittedPayload {
  if (String(payload.tool).toLowerCase() !== "message" || size(payload) <= budget) return { payload, partial: false };
  const out: Record<string, unknown> = { ...payload };
  const hasArgs = out.args !== null && typeof out.args === "object";
  const slots: Slot[] = [];
  if (hasArgs) {
    // The gateway reads the text from the params, so a copy of it in content is not needed.
    delete out.content;
    out.args = structuredClone(out.args);
    collect(out.args, slots, new Set(), 0);
  } else if (typeof out.content === "string") {
    slots.push({ container: out, key: "content", length: out.content.length });
  }
  const read = (s: Slot) => (s.container as Record<string, unknown>)[s.key as string] as string;
  // First the attachments: their bytes are no text anyone reads. A value in an
  // attachment field that is not base64 is text and is cut like any other.
  for (const slot of slots) {
    const value = read(slot);
    if (
      typeof slot.key === "string" && ATTACHMENT_KEYS.has(slot.key.toLowerCase()) &&
      value.length >= ATTACHMENT_MIN_CHARS && isBase64Payload(value)
    ) {
      (slot.container as Record<string, unknown>)[slot.key as string] = describeAttachment(value);
      slot.length = read(slot).length;
    }
  }
  // Then the longest strings, once, as little as the call needs. Each attempt
  // cuts a fresh copy of the call, so no string is cut twice.
  if (size(out) > budget && hasArgs) {
    for (const safety of CUT_SAFETIES) {
      const trial: Record<string, unknown> = { ...out, args: structuredClone(out.args) };
      const trialSlots: Slot[] = [];
      collect(trial.args, trialSlots, new Set(), 0);
      if (cutLongest(trial, trialSlots, budget, safety) && size(trial) <= budget) {
        return { payload: { ...trial, args_partial: true }, partial: true };
      }
    }
  } else if (size(out) > budget) {
    cutLongest(out, slots, budget, CUT_SAFETIES[1]);
  }
  // A call that still does not fit (numbers and short values past the cut) is
  // sent as a note: its routing values and its text, cut to the room left.
  if (size(out) > budget) {
    const note = "call too large to send: attachments and the rest of the structure are not sent";
    const rest = { ...out, args: { ...collectRouting(payload.args), note } };
    const room = budget - size(rest) - 1024;
    const text = collectText(payload.args);
    const bytesPerChar = text === "" ? 1 : Math.max(1, Buffer.byteLength(JSON.stringify(text)) / text.length);
    const limit = Math.floor((room / bytesPerChar) * CUT_SAFETIES[1]);
    const kept = text === "" || room <= MIN_CUT_CHARS ? "" : limit >= text.length ? text : cutString(text, Math.max(limit, MIN_CUT_CHARS));
    out.args = { ...collectRouting(payload.args), ...(kept === "" ? {} : { text: kept }), note };
    if (size(out) > budget && kept !== "") out.args = { ...collectRouting(payload.args), note };
  }
  out.args_partial = true;
  return { payload: out, partial: true };
}
