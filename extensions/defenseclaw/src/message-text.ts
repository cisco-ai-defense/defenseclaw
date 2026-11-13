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

/**
 * The text of an OpenClaw `message` tool call (GAP-0177, GAP-0290..0292).
 *
 * OpenClaw channels name the message text differently: `content`, `body`,
 * `text`, `message`, `caption`, or text nested in blocks and attachments. The
 * plugin used to read only `content` and `body` and skipped inspection when
 * neither was set, so a call that carried its text in any other field was
 * never inspected. This walk reads every string in the params instead.
 *
 * It must give the same answers as extractMessageArgs in
 * internal/gateway/message_text.go; internal/gateway/testdata/
 * message_text_parity.json holds the cases both sides run. The gateway reads
 * the params itself as well, so the limits and the routing values never depend
 * on this copy; it sends the text it read as the call's `content`.
 */

/** Total UTF-8 bytes returned. A longer text keeps its head and its tail. */
export const MESSAGE_TEXT_MAX_BYTES = 256 * 1024;
/** Nesting depth below the params object. */
const MAX_DEPTH = 8;
/**
 * Values of any kind walked in one call (a string, a number, an object, an
 * array, a routing string). It bounds the walk and the join; a 700-row table
 * is within it.
 */
const MAX_NODES = 4096;
/** The length from which a base64 value of an attachment field is a payload. */
const PAYLOAD_MIN_CHARS = 1024;
/** How much of a value the base64 check reads. */
const PAYLOAD_PROBE_CHARS = 4096;

/** Fields that usually hold the message text. They are read first, in order. */
const TEXT_KEYS = [
  "content", "body", "text", "message", "caption", "subject", "title",
  "summary", "description", "html", "markdown", "blocks", "attachments",
  "voicetext", "quotetext", "presentation",
];

/**
 * Routing and control fields. They name where the message goes or how to send
 * it, not what it says; a phone number or an address in `to` would only make
 * the content rules alert on every message. A string under one of them is not
 * scanned as text: it is a routing value, which the gateway reads through the
 * tool policy like the destination of any other send tool.
 */
const ROUTING_KEYS = new Set([
  "action", "channel", "provider", "accountid", "account", "to", "target",
  "targets", "from", "recipient", "recipients", "replyto", "threadid",
  "messageid", "chatid", "id", "type", "kind", "mode", "format", "parsemode",
  "silent", "dryrun", "timeoutms", "besteffort", "gatewayurl",
  "gatewaytoken",
]);

export interface MessageExtract {
  /** Every string outside the routing values, joined by newlines. */
  text: string;
  /**
   * A read limit was hit: more values than the node limit, a value below the
   * depth limit, or a text past the size limit. Over the limits is unknown,
   * never clean (the gateway floors the call at the unknown tier of its
   * policy; it reads the params itself, routing values included).
   */
  overCap: boolean;
}

/**
 * Reads the params of a message call. Numbers are text too (a table cell, a
 * count the message states), read as String(n).
 */
export function extractMessage(params: unknown): MessageExtract {
  const state: WalkState = { parts: [], nodes: 0, overCap: false };
  walk(params, 0, "", state);
  let text = state.parts.join("\n");
  // A character is at most 3 UTF-8 bytes per UTF-16 unit, so a short text
  // needs no byte count.
  if (text.length * 3 > MESSAGE_TEXT_MAX_BYTES) {
    const bytes = new TextEncoder().encode(text);
    if (bytes.length > MESSAGE_TEXT_MAX_BYTES) {
      // Head and tail, each cut at the start of a character.
      const half = MESSAGE_TEXT_MAX_BYTES >> 1;
      let head = half;
      while (head > 0 && (bytes[head] & 0xc0) === 0x80) head--;
      let tail = bytes.length - half;
      while (tail < bytes.length && (bytes[tail] & 0xc0) === 0x80) tail++;
      const decoder = new TextDecoder();
      text = `${decoder.decode(bytes.subarray(0, head))}\n${decoder.decode(bytes.subarray(tail))}`;
      state.overCap = true;
    }
  }
  return { text, overCap: state.overCap };
}

interface WalkState {
  parts: string[];
  nodes: number;
  overCap: boolean;
}

/** Lowercases the ASCII letters only, as the gateway does: key names match on it. */
function asciiLower(s: string): string {
  return s.replace(/[A-Z]/g, (c) => String.fromCharCode(c.charCodeAt(0) + 32));
}

/** Orders by code point: the byte order of UTF-8, which the gateway sorts by. */
function compareCodePoints(a: string, b: string): number {
  const x = Array.from(a);
  const y = Array.from(b);
  for (let i = 0; i < x.length && i < y.length; i++) {
    const d = x[i].codePointAt(0)! - y[i].codePointAt(0)!;
    if (d !== 0) return d;
  }
  return x.length - y.length;
}

function leaf(text: string, state: WalkState): void {
  if (text.trim() !== "") state.parts.push(text);
}

function walk(value: unknown, depth: number, path: string, state: WalkState): void {
  if (state.nodes >= MAX_NODES) {
    state.overCap = true;
    return;
  }
  state.nodes++;
  if (typeof value === "string") {
    leaf(value, state);
    return;
  }
  if (typeof value === "number") {
    if (Number.isFinite(value)) leaf(String(value), state);
    return;
  }
  if (value === null || typeof value !== "object") return;
  if (depth > MAX_DEPTH) {
    state.overCap = true;
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) walk(item, depth + 1, path, state);
    return;
  }
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record);
  const rank = (key: string): number => {
    const i = TEXT_KEYS.indexOf(asciiLower(key));
    return i < 0 ? TEXT_KEYS.length : i;
  };
  keys.sort((a, b) => rank(a) - rank(b) || compareCodePoints(a, b));
  for (const key of keys) {
    const child = path === "" ? key : `${path}.${key}`;
    if (ROUTING_KEYS.has(asciiLower(key)) && routingValue(record[key], state)) continue;
    const field = record[key];
    if (typeof field === "string" && binaryPayload(key, field)) {
      // An attachment's bytes are not message text and do not spend the text budget.
      state.nodes++;
      continue;
    }
    walk(field, depth + 1, child, state);
  }
}

/**
 * Counts the strings of a routing key's value against the node budget (the
 * gateway reads them through the tool policy) and reports whether the value
 * held nothing else. A routing key that holds an object (a target with its own
 * text) is read like any other: its strings are text and the routing keys
 * inside it count their own.
 */
function routingValue(value: unknown, state: WalkState): boolean {
  if (typeof value === "string") {
    countRouting(value, state);
    return true;
  }
  if (Array.isArray(value)) {
    if (value.some((item) => item !== null && typeof item === "object")) return false;
    for (const item of value) {
      if (typeof item === "string") countRouting(item, state);
    }
    return true;
  }
  return value === null || typeof value !== "object";
}

function countRouting(value: string, state: WalkState): void {
  if (value.trim() === "") return;
  if (state.nodes >= MAX_NODES) {
    state.overCap = true;
    return;
  }
  state.nodes++;
}

const BASE64_CHARS = /^[A-Za-z0-9+/_=\r\n-]*$/;

/**
 * An attachment's bytes: a long base64 value in the buffer field (OpenClaw's
 * "Base64/data-URL attachment") or a base64 data URL anywhere. It is no
 * message text; a value that does not read as base64 is.
 */
function binaryPayload(key: string, value: string): boolean {
  if (value.length < PAYLOAD_MIN_CHARS) return false;
  let payload = value;
  if (value.startsWith("data:")) {
    const i = value.slice(0, 256).indexOf(";base64,");
    if (i < 0) return false;
    payload = value.slice(i + ";base64,".length);
  } else if (asciiLower(key) !== "buffer") {
    return false;
  }
  return payload.length >= PAYLOAD_MIN_CHARS && BASE64_CHARS.test(payload.slice(0, PAYLOAD_PROBE_CHARS));
}
