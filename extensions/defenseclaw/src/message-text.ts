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
/** String and number values read in one call. */
const MAX_LEAVES = 512;
/** Values of any kind walked in one call. */
const MAX_NODES = 4096;

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
   * Text the read limits dropped: more strings than the leaf limit, more
   * values than the node limit, a string below the depth limit, or a text
   * past the size limit. Over the limits is unknown, never clean.
   */
  overCap: boolean;
  /** The strings under routing keys, by dotted key path (a repeat gets #2, #3). */
  routing: Record<string, string>;
}

/**
 * Reads the params of a message call. Numbers are text too (a table cell, a
 * count the message states), read as String(n).
 */
export function extractMessage(params: unknown): MessageExtract {
  const state: WalkState = { parts: [], leaves: 0, nodes: 0, overCap: false, routing: {} };
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
  return { text, overCap: state.overCap, routing: state.routing };
}

interface WalkState {
  parts: string[];
  leaves: number;
  nodes: number;
  overCap: boolean;
  routing: Record<string, string>;
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
  if (text.trim() === "") return;
  if (state.leaves >= MAX_LEAVES) {
    state.overCap = true;
    return;
  }
  state.leaves++;
  state.parts.push(text);
}

function walk(value: unknown, depth: number, path: string, state: WalkState): void {
  if (state.nodes >= MAX_NODES) {
    state.overCap = state.overCap || hasText(value, 0);
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
    state.overCap = state.overCap || hasText(value, 0);
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
    if (ROUTING_KEYS.has(asciiLower(key)) && routingValue(child, record[key], state)) continue;
    walk(record[key], depth + 1, child, state);
  }
}

/**
 * Files the strings of a routing key's value and reports whether the value
 * held nothing else. A routing key that holds an object (a target with its own
 * text) is read like any other: its strings are text and the routing keys
 * inside it file their own.
 */
function routingValue(path: string, value: unknown, state: WalkState): boolean {
  if (typeof value === "string") {
    if (value.trim() !== "") fileRouting(path, value, state);
    return true;
  }
  if (Array.isArray(value)) {
    if (value.some((item) => item !== null && typeof item === "object")) return false;
    for (const item of value) {
      if (typeof item === "string" && item.trim() !== "") fileRouting(path, item, state);
    }
    return true;
  }
  return value === null || typeof value !== "object";
}

function fileRouting(path: string, value: string, state: WalkState): void {
  let key = path;
  for (let n = 2; key in state.routing; n++) key = `${path}#${n}`;
  state.routing[key] = value;
}

/** True when the value holds a non-blank string or a number. Bounded, so a cyclic object ends. */
function hasText(value: unknown, depth: number): boolean {
  if (typeof value === "string") return value.trim() !== "";
  if (typeof value === "number") return Number.isFinite(value);
  if (value === null || typeof value !== "object" || depth > 64) return false;
  const items = Array.isArray(value) ? value : Object.values(value as Record<string, unknown>);
  return items.some((item) => hasText(item, depth + 1));
}
