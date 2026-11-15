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
// gateway reads its request body limit, its attachment fields and its data URL
// header window from the same file.
import limits from "./inspect-tool-request-limits.json" with { type: "json" };

/**
 * Fits a message call to the gateway's request body limit
 * (rel-1-0-10:GAP-0356, GAP-0402, GAP-0436).
 *
 * The plugin sends a message call as it is, the params and nothing else: the
 * gateway reads the text, the recipients and the attachments out of them, and
 * judges them as the rules of its pack say. A call that fits the limit is sent
 * whole, up to the byte.
 *
 * A call over the limit never has its text cut. Only an attachment (a long
 * base64 value of an attachment field, at any depth) is replaced, by its size,
 * media type and SHA-256 and the text the gateway would have read in it (the
 * runs of text of its bytes, as messageAttachmentText reads them): a photo
 * becomes a few bytes, and a key in a file sent as an attachment still reaches
 * the rules. An attachment past what one call reads (ATTACHMENT_READ_MAX_CHARS)
 * is replaced by a not-read descriptor, its size and type only: the text of
 * the call fits, only that attachment cannot be read (GAP-0512). A call that
 * then fits is sent with `args_partial: true` (the bytes were not sent, so the
 * gateway judges it at least at the unknown tier of its pack: alert in the
 * default and permissive packs, block in strict, never allow). A call that
 * still does not fit, because its text alone (or the text in its attachments)
 * is over the limit, is refused here and blocked in every pack, as rel's
 * gateway refused it (400, a failed check). So is a call with a not-read
 * attachment and a `content` or `body`: rel sent those calls, and its gateway
 * refused them for their size, so the part nobody read stays blocked. Any
 * other tool is never changed here: the gateway refuses it as it always has
 * and the check fails closed.
 *
 * Known limit (no gap, the GAP-0356 class): the gateway reads an attachment
 * only for the text of its decoded bytes, so the descriptor carries only that.
 * Text in a raw base64-alphabet value (key lines in `buffer`), in the
 * parameters of an ASCII data URL header, or in an attachment nested past the
 * gateway's depth 8 (TRUNCATED, the unknown tier) is not read on either side.
 */

/**
 * The most a request body may be: the gateway reads, and a call is sent as it
 * is, up to exactly this (the client sends JSON.stringify of the payload).
 */
export const GATEWAY_BODY_LIMIT_BYTES = limits.body_max_bytes;

/** The reason a message call over the limit is blocked. */
export const MESSAGE_TEXT_OVER_LIMIT = "message text exceeds the inspection limit";

/** ASCII-only lower case, as the gateway's asciiLowerPreservingBytes folds a field name. */
const asciiLower = (s: string) => s.replace(/[A-Z]+/g, (m) => m.toLowerCase());
/** The fields that carry an attachment, at any depth (the gateway's messageAttachmentField). */
const ATTACHMENT_KEYS = new Set(limits.message_attachment_keys.map(asciiLower));
/**
 * The bytes from the start of a data URL within which its ";base64," must end
 * (the gateway's messageDataURLHeaderMaxBytes, from the same file). UTF-8
 * bytes, not UTF-16 units: a header with non-ASCII characters in it is text to
 * the gateway once the marker is past this many bytes (GAP-0511).
 */
const DATA_URL_HEADER_MAX_BYTES = limits.message_data_url_header_max_bytes;
const BASE64_MARKER = ";base64,";
/**
 * An attachment field's value this long is replaced by its descriptor. It is
 * deliberately larger than the gateway's messagePayloadMinBytes (1024): a value
 * between the two is kept as it is (or the call refused), never described, so
 * the plugin describes only what the gateway also reads as an attachment.
 */
const ATTACHMENT_MIN_CHARS = 4096;
/**
 * The base64 characters of attachments one call decodes for their text (24 MiB
 * of bytes, a few phone photos, well under a second). An attachment past it is
 * not read: it gets a not-read descriptor (GAP-0512).
 */
const ATTACHMENT_READ_MAX_CHARS = 32 << 20;
/** The shortest run of text bytes read out of an attachment (messageRunMinBytes). */
const RUN_MIN_BYTES = 16;
/** How much of a decoded attachment is looked at to tell UTF-16 text (messageUTF16ProbeBytes). */
const UTF16_PROBE_BYTES = 4096;

/**
 * A value of base64 characters (either alphabet) and padding, wrapped at line
 * breaks, all through. A value with a space or a tab in it is not one here: the
 * gateway reads it as text as well as decoding it (messageLenientBase64), so
 * the plugin keeps it as text.
 */
const BASE64_ALL = /^[A-Za-z0-9+/_=\n\r\f\v-]*$/;

export interface FittedPayload {
  payload: Record<string, unknown>;
  /** True when the bytes of an attachment were not sent. */
  partial: boolean;
  /** Set when the call cannot be sent without cutting its text: block it with this reason. */
  refused?: string;
}

function size(payload: unknown): number {
  return Buffer.byteLength(JSON.stringify(payload) ?? "");
}

/** The six bits of each base64 character (either alphabet); 64 white space, 65 "=", 255 anything else. */
const B64 = (() => {
  const t = new Uint8Array(256).fill(255);
  const std = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  for (let i = 0; i < std.length; i++) t[std.charCodeAt(i)] = i;
  t[45] = 62; // -
  t[95] = 63; // _
  for (const c of " \t\n\r\f\v") t[c.charCodeAt(0)] = 64;
  t[61] = 65; // =
  return t;
})();

/**
 * Decodes base64 as the gateway's messageBase64Reader does: white space is
 * skipped, either alphabet is read, and "=" drops the bits of the group it
 * ends and starts the next group fresh.
 */
function decodeLenient(s: string): Buffer {
  const out = Buffer.allocUnsafe(Math.ceil((s.length * 3) / 4));
  let n = 0;
  let acc = 0;
  let bits = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    const v = c < 256 ? B64[c] : 255;
    if (v < 64) {
      acc = ((acc << 6) | v) & 0xffffff;
      bits += 6;
      if (bits >= 8) {
        bits -= 8;
        out[n++] = (acc >> bits) & 0xff;
        acc &= (1 << bits) - 1;
      }
    } else if (v === 65) {
      acc = 0;
      bits = 0;
    }
  }
  return out.subarray(0, n);
}

/** Go's unicode.IsPrint for a code point above ASCII: letters, marks, numbers, punctuation and symbols. */
const PRINTABLE = /^[\p{L}\p{M}\p{N}\p{P}\p{S}]$/u;

/**
 * The length of the valid UTF-8 character at buf[i] (Go's utf8.DecodeRune
 * rules: no overlong forms, no surrogates, nothing past U+10FFFF) and its code
 * point, or 0 for an invalid byte.
 */
function utf8At(buf: Buffer, i: number): [number, number] {
  const b0 = buf[i];
  const cont = (k: number) => i + k < buf.length && (buf[i + k] & 0xc0) === 0x80;
  if (b0 >= 0xc2 && b0 <= 0xdf && cont(1)) return [2, ((b0 & 0x1f) << 6) | (buf[i + 1] & 0x3f)];
  if (b0 >= 0xe0 && b0 <= 0xef && cont(1) && cont(2)) {
    const cp = ((b0 & 0x0f) << 12) | ((buf[i + 1] & 0x3f) << 6) | (buf[i + 2] & 0x3f);
    return cp < 0x800 || (cp >= 0xd800 && cp <= 0xdfff) ? [0, 0] : [3, cp];
  }
  if (b0 >= 0xf0 && b0 <= 0xf4 && cont(1) && cont(2) && cont(3)) {
    const cp = ((b0 & 0x07) << 18) | ((buf[i + 1] & 0x3f) << 12) | ((buf[i + 2] & 0x3f) << 6) | (buf[i + 3] & 0x3f);
    return cp < 0x10000 || cp > 0x10ffff ? [0, 0] : [4, cp];
  }
  return [0, 0];
}

/**
 * The runs of at least RUN_MIN_BYTES text bytes (printable characters and
 * white space of valid UTF-8) joined by newlines, as the gateway's
 * messageStreamTextRuns reads them.
 */
function textRuns(buf: Buffer): string {
  const out: string[] = [];
  let start = 0;
  const flush = (end: number) => {
    if (end - start >= RUN_MIN_BYTES) out.push(buf.toString("utf8", start, end));
  };
  let i = 0;
  while (i < buf.length) {
    const c = buf[i];
    if (c < 0x80) {
      if ((c >= 0x20 && c < 0x7f) || c === 0x0a || c === 0x0d || c === 0x09) {
        i++;
      } else {
        flush(i);
        i++;
        start = i;
      }
      continue;
    }
    const [len, cp] = utf8At(buf, i);
    if (len === 0 || !PRINTABLE.test(String.fromCodePoint(cp))) {
      flush(i);
      i++;
      start = i;
    } else {
      i += len;
    }
  }
  flush(i);
  return out.join("\n");
}

/** UTF-16 text and its byte order, as the gateway's messageUTF16 tells it. */
function utf16Of(head: Buffer): { be: boolean; bom: boolean } | undefined {
  if (head.length >= 2) {
    if (head[0] === 0xff && head[1] === 0xfe) return { be: false, bom: true };
    if (head[0] === 0xfe && head[1] === 0xff) return { be: true, bom: true };
  }
  const pairs = head.length >> 1;
  if (pairs < 16) return undefined;
  let even = 0;
  let odd = 0;
  for (let i = 0; i + 1 < head.length; i += 2) {
    if (head[i] === 0) even++;
    if (head[i + 1] === 0) odd++;
  }
  if (odd * 10 >= pairs * 3 && even * 50 <= pairs) return { be: false, bom: false };
  if (even * 10 >= pairs * 3 && odd * 50 <= pairs) return { be: true, bom: false };
  return undefined;
}

/**
 * The text of a base64 payload, as the gateway's messageAttachmentText reads
 * it: the runs of its 8-bit reading and, when it looks like UTF-16, the runs of
 * that reading too.
 */
function attachmentText(payload: string): string {
  const bytes = decodeLenient(payload);
  let text = textRuns(bytes);
  const u16 = utf16Of(bytes.subarray(0, UTF16_PROBE_BYTES));
  if (u16) {
    const words = Buffer.from(bytes.subarray(0, bytes.length & ~1));
    if (u16.be) words.swap16();
    let s = words.toString("utf16le");
    if (u16.bom && s.charCodeAt(0) === 0xfeff) s = s.slice(1);
    // Lone surrogates become U+FFFD, as Go's utf16.Decode makes them.
    const runs = textRuns(Buffer.from(s, "utf8"));
    if (text === "") text = runs;
    else if (runs !== "" && runs !== text) text += `\n${runs}`;
  }
  return text;
}

/**
 * The base64 part of a long attachment value (bare, or behind a base64 data URL
 * header whose marker ends within DATA_URL_HEADER_MAX_BYTES bytes, as the
 * gateway's messageWalk.attachment reads it), or undefined.
 */
function base64Payload(value: string): string | undefined {
  let payload = value;
  if (value.startsWith("data:")) {
    // A marker past the window in characters is past it in bytes too, so the
    // character slice only bounds the search; the byte count decides.
    const i = value.slice(0, DATA_URL_HEADER_MAX_BYTES).indexOf(BASE64_MARKER);
    const end = i + BASE64_MARKER.length;
    if (i < 0 || Buffer.byteLength(value.slice(0, end)) > DATA_URL_HEADER_MAX_BYTES) return undefined;
    payload = value.slice(end);
  }
  return BASE64_ALL.test(payload) ? payload : undefined;
}

/**
 * The descriptor of an attachment value: what the gateway can judge without
 * its bytes, and the text it would have read in them. An attachment past the
 * read budget (read false) says so and carries no text: the gateway judges it
 * at the unknown tier, as it judges any part of a call it did not read.
 */
function describeAttachment(value: string, payload: string, read: boolean): string {
  const mime = /^data:([^;,]*)[;,]/.exec(value.slice(0, DATA_URL_HEADER_MAX_BYTES))?.[1] || "unknown type";
  const hash = createHash("sha256").update(value).digest("hex");
  const facts = `${value.length} characters, ${mime}, sha256 ${hash}`;
  if (!read) return `[attachment bytes not sent: ${facts}, not read: past the plugin's read budget]`;
  const text = attachmentText(payload);
  const head = `[attachment bytes not sent: ${facts}]`;
  return text === "" ? head : `${head}\n${text}`;
}

interface DescribeBudget {
  /** The base64 characters left to read. */
  chars: number;
  /** Attachments replaced by a descriptor with their text. */
  described: number;
  /** Attachments replaced by a not-read descriptor. */
  unread: number;
}

/**
 * Replaces each long base64 attachment value under value (in place) by its
 * descriptor: with its text while the read budget lasts, a not-read descriptor
 * past it.
 */
function describeAttachments(value: unknown, budget: DescribeBudget, depth: number): void {
  if (value === null || typeof value !== "object" || depth > 64) return;
  const container = value as Record<string, unknown>;
  for (const key of Object.keys(container)) {
    const item = container[key];
    if (typeof item === "string") {
      if (!Array.isArray(container) && ATTACHMENT_KEYS.has(asciiLower(key)) && item.length >= ATTACHMENT_MIN_CHARS) {
        const payload = base64Payload(item);
        if (payload === undefined) continue;
        const read = payload.length <= budget.chars;
        if (read) {
          budget.chars -= payload.length;
          budget.described++;
        } else {
          budget.unread++;
        }
        container[key] = describeAttachment(item, payload, read);
      }
    } else {
      describeAttachments(item, budget, depth + 1);
    }
  }
}

/**
 * True when rel's plugin sent this call to the gateway: it sent a message only
 * when `content` or `body` held something, and the gateway refused one over
 * the limit (400, a block).
 */
function relSent(args: Record<string, unknown>): boolean {
  return Boolean(args.content || args.body);
}

/**
 * Returns the payload to send, or the reason to block the call. The payload is
 * copied before an attachment is replaced; the caller's call is not changed.
 */
export function fitInspectBody(payload: Record<string, unknown>, limit = GATEWAY_BODY_LIMIT_BYTES): FittedPayload {
  // Whole while the body fits the gateway's limit (GAP-0436).
  if (String(payload.tool).toLowerCase() !== "message" || size(payload) <= limit) return { payload, partial: false };
  const refused = { payload, partial: false, refused: MESSAGE_TEXT_OVER_LIMIT };
  if (payload.args === null || typeof payload.args !== "object") return refused;
  const args = structuredClone(payload.args) as Record<string, unknown>;
  const budget: DescribeBudget = { chars: ATTACHMENT_READ_MAX_CHARS, described: 0, unread: 0 };
  describeAttachments(args, budget, 0);
  if (budget.described + budget.unread === 0) return refused;
  // An attachment nobody can read next to the text rel sent: blocked, as rel blocked it.
  if (budget.unread > 0 && relSent(args)) return refused;
  const out = { ...payload, args, args_partial: true };
  return size(out) <= limit ? { payload: out, partial: true } : refused;
}
