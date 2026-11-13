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
 * The text of an OpenClaw `message` tool call (GAP-0177).
 *
 * OpenClaw channels name the message text differently: `content`, `body`,
 * `text`, `message`, `caption`, or text nested in blocks and attachments. The
 * plugin used to read only `content` and `body` and skipped inspection when
 * neither was set, so a call that carried its text in any other field was
 * never inspected. This walk reads every string in the params instead.
 *
 * It must stay in step with messageTextFromArgs in
 * internal/gateway/message_text.go, which does the same for a caller that
 * sends the params without the text.
 */

/** Total characters returned. A longer text keeps its head and its tail. */
export const MESSAGE_TEXT_MAX_CHARS = 256 * 1024;
/** Nesting depth below the params object. */
const MAX_DEPTH = 8;
/** String values read in one call. */
const MAX_LEAVES = 512;

/** Fields that usually hold the message text. They are read first, in order. */
const TEXT_KEYS = [
  "content", "body", "text", "message", "caption", "subject", "title",
  "summary", "description", "html", "markdown", "blocks", "attachments",
];

/**
 * Routing and control fields. They name where the message goes or how to send
 * it, not what it says; a phone number or an address in `to` would only make
 * the content rules alert on every message. They stay in the `args` the
 * gateway receives and the tool-policy lane still reads them.
 */
const ROUTING_KEYS = new Set([
  "action", "channel", "provider", "accountid", "account", "to", "target",
  "targets", "from", "recipient", "recipients", "replyto", "threadid",
  "messageid", "chatid", "id", "type", "kind", "mode", "format", "parsemode",
  "silent", "dryrun", "timeoutms", "besteffort", "gatewayurl",
  "gatewaytoken",
]);

/**
 * Returns the text of a message call's params, or "" when it holds no string
 * outside the routing fields. The caller must not read "" as "nothing to
 * inspect": it sends the call through the generic tool inspection instead.
 */
export function extractMessageText(params: unknown): string {
  const parts: string[] = [];
  walk(params, 0, { leaves: 0 }, parts);
  const text = parts.join("\n");
  if (text.length <= MESSAGE_TEXT_MAX_CHARS) return text;
  const half = MESSAGE_TEXT_MAX_CHARS >> 1;
  return `${text.slice(0, half)}\n${text.slice(text.length - half)}`;
}

function walk(
  value: unknown,
  depth: number,
  state: { leaves: number },
  out: string[],
): void {
  if (typeof value === "string") {
    if (state.leaves >= MAX_LEAVES || value.trim() === "") return;
    state.leaves++;
    out.push(value);
    return;
  }
  if (depth > MAX_DEPTH || value === null || typeof value !== "object") return;
  if (Array.isArray(value)) {
    for (const item of value) walk(item, depth + 1, state, out);
    return;
  }
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record);
  const rank = (key: string): number => {
    const i = TEXT_KEYS.indexOf(key.toLowerCase());
    return i < 0 ? TEXT_KEYS.length : i;
  };
  keys.sort((a, b) => rank(a) - rank(b) || (a < b ? -1 : a > b ? 1 : 0));
  for (const key of keys) {
    if (ROUTING_KEYS.has(key.toLowerCase())) continue;
    walk(record[key], depth + 1, state, out);
  }
}
