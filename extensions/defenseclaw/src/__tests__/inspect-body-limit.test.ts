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
import { GATEWAY_BODY_LIMIT_BYTES, MESSAGE_TEXT_OVER_LIMIT, fitInspectBody } from "../inspect-body-limit.js";

const limits = JSON.parse(
  readFileSync(new URL("../../../../schemas/inspect-tool-request-limits.json", import.meta.url), "utf8"),
) as { body_max_bytes: number; message_attachment_keys: string[]; message_data_url_header_max_bytes: number };
/** The gateway's attachment test rows (GAP-0511): which data URL values are attachments, by bytes. */
const windowRows = JSON.parse(
  readFileSync(new URL("../../../../internal/gateway/testdata/message_attachment_window.json", import.meta.url), "utf8"),
) as {
  payload_unit: string;
  payload_repeat: number;
  cases: Array<{ name: string; fill: string; count: number; marker_end_bytes: number; attachment: boolean }>;
};
const LIMIT = limits.body_max_bytes;
const bodyBytes = (v: unknown) => Buffer.byteLength(JSON.stringify(v));
const KEY = "sk-ant-api03-" + "A7b9C2d4E6f8G1h3J5k7L9m2";
const prose = (n: number) => "the quarterly plan is attached for review. ".repeat(Math.ceil(n / 43) + 1).slice(0, n);
const wrap = (params: Record<string, unknown>) => ({ tool: "message", args: params, direction: "outbound", approval_surface: "native" });
const rows = (n: number) => Array.from({ length: n }, (_, r) => Array.from({ length: 10 }, (_, c) => r * 10 + c));
const b64 = (s: string | Buffer) => Buffer.from(s).toString("base64");
/** Bytes with no run of text in them (a photo's pixels). */
const noise = (n: number) => {
  const out = Buffer.alloc(n);
  for (let i = 0; i < n; i++) out[i] = (i * 7919 + 13) & 0xff;
  return out;
};
/** The smallest params mk(n) whose call is at least `target` bytes. */
const tune = (mk: (n: number) => Record<string, unknown>, target: number) => {
  let lo = 0;
  let hi = 2_000_000;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (bodyBytes(wrap(mk(mid))) < target) lo = mid + 1;
    else hi = mid;
  }
  return mk(lo);
};

describe("fitInspectBody", () => {
  it("has one source for the limit and the attachment fields: the file the gateway embeds", () => {
    expect(GATEWAY_BODY_LIMIT_BYTES).toBe(LIMIT);
    expect(limits.message_attachment_keys).toEqual(["buffer", "media"]);
    expect(limits.message_data_url_header_max_bytes).toBe(256);
  });

  it("sends a call of exactly the limit whole and refuses one byte more of text", () => {
    const text = "x".repeat(LIMIT - bodyBytes(wrap({ message: "" })));
    const atLimit = wrap({ message: text });
    expect(bodyBytes(atLimit)).toBe(LIMIT);
    const whole = fitInspectBody(atLimit);
    expect(whole.payload).toBe(atLimit);
    expect(whole.partial).toBe(false);
    expect(whole.refused).toBeUndefined();
    const got = fitInspectBody(wrap({ message: `${text}x` }));
    expect(got.refused).toBe(MESSAGE_TEXT_OVER_LIMIT);
    expect(got.partial).toBe(false);
  });

  it.each([1, 4, 16])("replaces the bytes of a %i MB attachment with its size, type and hash", (mb) => {
    const data = `data:image/png;base64,${"AAEC".repeat((mb << 20) / 4)}`;
    const payload = wrap({ message: "here is the photo", buffer: data, filename: "a.png" });
    const got = fitInspectBody(payload);
    expect(got.refused).toBeUndefined();
    expect(got.partial).toBe(true);
    expect(got.payload.args_partial).toBe(true);
    expect(bodyBytes(got.payload)).toBeLessThanOrEqual(LIMIT);
    const args = got.payload.args as Record<string, string>;
    expect(args.message).toBe("here is the photo");
    expect(args.buffer).toMatch(/^\[attachment bytes not sent: \d+ characters, image\/png, sha256 [0-9a-f]{64}\]$/);
    // The caller's own call is not changed.
    expect((payload.args as Record<string, string>).buffer).toBe(data);
  });

  // GAP-0356: a phone photo over the limit is sent as its descriptor and the
  // text the gateway would read in it (the camera's metadata), never blocked
  // for its size.
  it("sends a phone photo with a short caption as its descriptor and its metadata text", () => {
    const jpeg = Buffer.concat([
      Buffer.from([0xff, 0xd8, 0xff, 0xe1, 0x10, 0x00]),
      Buffer.from("Exif\0\0MM\0*\0\0\0\x08"),
      Buffer.from("Apple\0iPhone 15 Pro Max\0"),
      Buffer.from('<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:Description photoshop:DateCreated="2026-11-01T09:12:44"/></x:xmpmeta>'),
      noise(3 << 20),
    ]);
    const params = { action: "sendAttachment", to: "+15550001111", caption: "the view from the office", buffer: `data:image/jpeg;base64,${b64(jpeg)}` };
    const got = fitInspectBody(wrap(params));
    expect(got.refused).toBeUndefined();
    expect(got.partial).toBe(true);
    const args = got.payload.args as Record<string, string>;
    expect(args.caption).toBe(params.caption);
    expect(args.to).toBe(params.to);
    expect(args.buffer).toMatch(/^\[attachment bytes not sent: \d+ characters, image\/jpeg, sha256 [0-9a-f]{64}\]\n/);
    expect(args.buffer).toContain("iPhone 15 Pro Max");
    expect(args.buffer).toContain("x:xmpmeta");
    expect(bodyBytes(got.payload)).toBeLessThan(8 * 1024);
  });

  // The review's two over-limit shapes: rel's gateway refused them (400) and
  // rel failed closed. The key sits in the middle of the text, which is never
  // cut: the call is refused, so it is blocked in every pack.
  it.each([
    ["grid-body-mid-1100k", () => tune((n) => ({ action: "send", to: "+15551230000", body: `${prose(n)}key: ${KEY}${prose(n)}` }), 1_100_000)],
    ["note-keymid-1400k", () => tune((n) => ({ action: "send", to: "+15551230000", body: `${prose(n)}key: ${KEY}${prose(n)}`, presentation: { blocks: [{ type: "table", rows: rows(12500) }] } }), 1_400_000)],
    ["grid-message-mid-1100k", () => tune((n) => ({ action: "send", to: "+15551230000", message: `${prose(n)}key: ${KEY}${prose(n)}` }), 1_100_000)],
  ])("refuses %s: the text is never cut", (_name, mk) => {
    const payload = wrap(mk());
    expect(bodyBytes(payload)).toBeGreaterThan(LIMIT);
    const got = fitInspectBody(payload);
    expect(got.refused).toBe(MESSAGE_TEXT_OVER_LIMIT);
    expect(got.payload).toBe(payload);
    expect(got.partial).toBe(false);
  });

  it.each(["content", "body", "message", "caption", "subject", "text", "html", "notes"])(
    "refuses a call whose %s alone is over the limit, next to a photo",
    (field) => {
      const got = fitInspectBody(wrap({ to: "+1", [field]: `${prose(600_000)} ${KEY} ${prose(600_000)}`, buffer: b64(noise(1 << 20)) }));
      expect(got.refused).toBe(MESSAGE_TEXT_OVER_LIMIT);
    },
  );

  it("sends text just under the limit whole next to a large attachment", () => {
    const photo = `data:image/png;base64,${b64(noise(2 << 20))}`;
    const room = LIMIT - bodyBytes(wrap({ message: "", buffer: "" })) - 400;
    const text = `${prose((room >> 1) - 40)} key: ${KEY} ${prose((room >> 1) - 40)}`;
    const payload = wrap({ message: text, buffer: photo });
    expect(bodyBytes(payload)).toBeGreaterThan(LIMIT);
    const got = fitInspectBody(payload);
    expect(got.refused).toBeUndefined();
    expect(got.partial).toBe(true);
    expect(bodyBytes(got.payload)).toBeLessThanOrEqual(LIMIT);
    const args = got.payload.args as Record<string, string>;
    expect(args.message).toBe(text);
    expect(args.message).toContain(KEY);
    expect(args.buffer).toMatch(/^\[attachment bytes not sent: /);
  });

  it("refuses text under the limit next to an attachment when the descriptor does not fit with it", () => {
    const text = "x".repeat(LIMIT - bodyBytes(wrap({ message: "", buffer: "" })) - 10);
    const got = fitInspectBody(wrap({ message: text, buffer: b64(noise(1 << 20)) }));
    expect(got.refused).toBe(MESSAGE_TEXT_OVER_LIMIT);
  });

  // A key inside an attachment: at the limit the call is sent whole and the
  // gateway decodes the attachment; just over it the descriptor carries the
  // text of the file, so the key still reaches the rules; when that text is
  // itself over the limit the call is refused (rel refused the call, 400).
  it("keeps the key of a text file sent as an attachment, at and over the limit", () => {
    const file = (n: number) => `${prose(n)}\nkey: ${KEY}\n${prose(n)}`;
    const mk = (n: number) => ({ action: "sendAttachment", to: "+1", caption: "see file", buffer: b64(file(n)) });
    // The largest n whose call fits the limit: one more is over it.
    let at = 0;
    for (let hi = 600_000; at < hi;) {
      const mid = (at + hi + 1) >> 1;
      if (bodyBytes(wrap(mk(mid))) <= LIMIT) at = mid;
      else hi = mid - 1;
    }
    const whole = wrap(mk(at));
    expect(fitInspectBody(whole).payload).toBe(whole);
    const over = fitInspectBody(wrap(mk(at + 1)));
    expect(over.refused).toBeUndefined();
    expect(over.partial).toBe(true);
    expect((over.payload.args as Record<string, string>).buffer).toContain(`key: ${KEY}`);
    expect(bodyBytes(over.payload)).toBeLessThanOrEqual(LIMIT);
    // A text file whose text is over the limit: nothing can be sent whole.
    expect(fitInspectBody(wrap(mk(800_000))).refused).toBe(MESSAGE_TEXT_OVER_LIMIT);
  });

  it("reads an attachment as the gateway does: UTF-16, a binary header, padding inside", () => {
    const u16text = `key: ${KEY} in a UTF-16 file. `.repeat(60);
    const u16le = Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(u16text, "utf16le")]);
    // No byte order mark: told by the NUL beside every other byte.
    const u16be = Buffer.from(u16text, "utf16le").swap16();
    const binaryHead = Buffer.concat([noise(8192), Buffer.from(`\nkey: ${KEY}\n`), noise(8192)]);
    // Two base64 values one after the other: the "=" of the first ends a group.
    const joined = b64(`${prose(5001)}k`) + b64(`ey: ${KEY}`);
    expect(b64(`${prose(5001)}k`)).toMatch(/=$/);
    for (const [name, buffer] of [
      ["utf16le", b64(u16le)],
      ["utf16be", b64(u16be)],
      ["binary head", b64(binaryHead)],
      ["data url", `data:application/octet-stream;base64,${b64(binaryHead)}`],
      ["wrapped", b64(binaryHead).replace(/.{76}/g, "$&\r\n")],
    ] as const) {
      const got = fitInspectBody(wrap({ message: "file", buffer, filler: "y".repeat(LIMIT) }));
      expect(got.refused, name).toBe(MESSAGE_TEXT_OVER_LIMIT);
      const fitted = fitInspectBody(wrap({ message: "file", media: buffer, other: { buffer: b64(noise(1 << 20)) } }));
      expect(fitted.partial, name).toBe(true);
      expect((fitted.payload.args as Record<string, string>).media, name).toContain(`key: ${KEY}`);
    }
    const pad = fitInspectBody(wrap({ message: "file", buffer: joined, photo: { media: b64(noise(1 << 20)) } }));
    expect(pad.partial).toBe(true);
    expect((pad.payload.args as Record<string, string>).buffer).toContain(`key: ${KEY}`);
  });

  it("keeps an attachment field that is not base64 as text: it is never described", () => {
    // Plain words, base64 with spaces in it (the gateway reads both readings), a data URL that is not base64.
    for (const buffer of ["word ".repeat(300_000), `${b64(noise(6000))} ${"x".repeat(1_200_000)}`, `data:text/plain,${"x".repeat(1_200_000)}`]) {
      const got = fitInspectBody(wrap({ message: "hi", buffer }));
      expect(got.refused).toBe(MESSAGE_TEXT_OVER_LIMIT);
      expect(got.payload.args).toEqual({ message: "hi", buffer });
    }
    // Under 4,096 characters an attachment is left as it is.
    const small = b64(noise(3000));
    const got = fitInspectBody(wrap({ message: "hi", buffer: small, media: b64(noise(1 << 20)) }));
    expect(got.partial).toBe(true);
    expect((got.payload.args as Record<string, string>).buffer).toBe(small);
  });

  it("describes an attachment at any depth and in any case of its field name", () => {
    const photo = b64(noise(1 << 20));
    const got = fitInspectBody(wrap({ message: "two photos", attachments: [{ Buffer: photo, name: "a.png" }, { MEDIA: photo }] }));
    expect(got.partial).toBe(true);
    const list = (got.payload.args as { attachments: Array<Record<string, string>> }).attachments;
    expect(list[0].Buffer).toMatch(/^\[attachment bytes not sent/);
    expect(list[0].name).toBe("a.png");
    expect(list[1].MEDIA).toMatch(/^\[attachment bytes not sent/);
  });

  // GAP-0512: an attachment past what one call reads is sent as a not-read
  // descriptor (size, type, hash, "not read"), so the gateway judges the call
  // at the unknown tier of its pack; the text still fits and is sent whole.
  const NOT_READ = /^\[attachment bytes not sent: \d+ characters, [^,]+, sha256 [0-9a-f]{64}, not read: past the plugin's read budget\]$/;
  it.each([
    ["ben-photo-30m-caption", 30_000_000],
    ["ben-photo-40m-caption", 40 << 20],
  ])("sends %s with a not-read descriptor, never refused", (_name, n) => {
    const params = { to: "+1", caption: "our trip", buffer: `data:image/jpeg;base64,${b64(noise(n))}` };
    const got = fitInspectBody(wrap(params));
    expect(got.refused).toBeUndefined();
    expect(got.partial).toBe(true);
    expect(got.payload.args_partial).toBe(true);
    const args = got.payload.args as Record<string, string>;
    expect(args.caption).toBe("our trip");
    expect(args.buffer).toMatch(NOT_READ);
    expect(args.buffer).toContain("image/jpeg");
    expect(bodyBytes(got.payload)).toBeLessThan(4096);
  });

  it("reads attachments while the budget lasts and sends the rest not read", () => {
    const first = b64(Buffer.concat([noise(20 << 20), Buffer.from(`\nkey: ${KEY}\n`)]));
    const got = fitInspectBody(wrap({ message: "two files", attachments: [{ buffer: first }, { buffer: b64(noise(20 << 20)) }] }));
    expect(got.partial).toBe(true);
    const list = (got.payload.args as { attachments: Array<Record<string, string>> }).attachments;
    expect(list[0].buffer).toContain(`key: ${KEY}`);
    expect(list[0].buffer).not.toContain("not read");
    expect(list[1].buffer).toMatch(NOT_READ);
  });

  // rel sent a message with content or body, and its gateway refused one over
  // the limit (400): with an attachment nobody read, that call stays refused.
  it.each(["content", "body"])("refuses a not-read attachment next to a %s, as rel did", (field) => {
    const got = fitInspectBody(wrap({ to: "+1", [field]: "a video", buffer: "AAEC".repeat((33 << 20) / 4) }));
    expect(got.refused).toBe(MESSAGE_TEXT_OVER_LIMIT);
    const two = fitInspectBody(wrap({ [field]: "two photos", attachments: [{ buffer: b64(noise(13_000_000)) }, { buffer: b64(noise(13_000_000)) }] }));
    expect(two.refused).toBe(MESSAGE_TEXT_OVER_LIMIT);
  });

  it("still refuses text over the limit next to a not-read attachment", () => {
    const got = fitInspectBody(wrap({ to: "+1", caption: `${prose(1_100_000)} ${KEY}`, buffer: "AAEC".repeat((33 << 20) / 4) }));
    expect(got.refused).toBe(MESSAGE_TEXT_OVER_LIMIT);
  });

  // GAP-0511: a data URL is an attachment only when ";base64," ends within the
  // header window in BYTES, as the gateway reads it. The rows are the
  // gateway's own (message_attachment_window.json).
  it("calls the same data URL values attachments as the gateway does", () => {
    const payload = windowRows.payload_unit.repeat(windowRows.payload_repeat);
    for (const row of windowRows.cases) {
      const value = `data:text/plain;name=${row.fill.repeat(row.count)};base64,${payload}`;
      expect(Buffer.byteLength(value.slice(0, value.indexOf(";base64,") + 8)), row.name).toBe(row.marker_end_bytes);
      const got = fitInspectBody(wrap({ buffer: value }), 4096);
      if (row.attachment) {
        expect(got.partial, row.name).toBe(true);
        expect((got.payload.args as Record<string, string>).buffer, row.name).toMatch(/^\[attachment bytes not sent: /);
      } else {
        expect(got.refused, row.name).toBe(MESSAGE_TEXT_OVER_LIMIT);
      }
    }
  });

  // The review's round-7 shapes (GAP-0511): a non-ASCII header puts the marker
  // past 256 bytes but within 256 characters. The gateway reads such a value
  // as text, so over the limit the plugin refuses it (block, as rel), and
  // under the limit it is sent whole.
  const nonAsciiHdr = `data:text/plain;name=${"é".repeat(150)}`;
  const rawKeyLines = (n: number) => `${KEY}\n${"Q".repeat(60)}\n`.repeat(Math.ceil(n / 75)).slice(0, n);
  const shapes: Array<[string, (n: number) => Record<string, unknown>]> = [
    ["dataurl-nonascii-hdrkey-bin", (n) => ({ to: "+15550001111", body: "see the attached file", buffer: `${nonAsciiHdr};note=${KEY};base64,${b64(noise(n))}` })],
    ["dataurl-nonascii-hdr-rawpayload", (n) => ({ to: "+15550001111", body: "see the attached file", buffer: `${nonAsciiHdr};base64,${rawKeyLines(Math.round(n * 1.34))}` })],
  ];
  it.each(shapes)("refuses %s-over and sends %s-under whole", (_name, mk) => {
    const over = wrap(mk(1_200_000));
    const got = fitInspectBody(over);
    expect(got.refused).toBe(MESSAGE_TEXT_OVER_LIMIT);
    expect(got.payload).toBe(over);
    const under = wrap(mk(600_000));
    expect(bodyBytes(under)).toBeLessThanOrEqual(LIMIT);
    expect(fitInspectBody(under).payload).toBe(under);
  });

  it("still describes an ASCII data URL photo over the limit (dataurl-ascii-photo-over)", () => {
    const got = fitInspectBody(wrap({ to: "+15550001111", caption: "our trip", buffer: `data:image/jpeg;base64,${b64(noise(1_200_000))}` }));
    expect(got.partial).toBe(true);
    expect((got.payload.args as Record<string, string>).buffer).toMatch(/^\[attachment bytes not sent: \d+ characters, image\/jpeg, sha256 [0-9a-f]{64}\]$/);
  });

  it("changes only a message, whatever the case of its name: any other tool is sent whole", () => {
    const args = { command: "x".repeat(2 << 20) };
    for (const tool of ["exec", "write", "bash", "messages"]) {
      const payload = { tool, args };
      const got = fitInspectBody(payload);
      expect(got.partial).toBe(false);
      expect(got.refused).toBeUndefined();
      expect(got.payload).toBe(payload);
    }
    for (const tool of ["message", "Message", "MESSAGE"]) {
      expect(fitInspectBody({ tool, args: { message: "x".repeat(2 << 20) } }).refused).toBe(MESSAGE_TEXT_OVER_LIMIT);
      expect(fitInspectBody({ tool, args: { buffer: "AAEC".repeat(1 << 19) } }).partial).toBe(true);
    }
    expect(fitInspectBody({ tool: "message", content: "x".repeat(2 << 20) }).refused).toBe(MESSAGE_TEXT_OVER_LIMIT);
  });

  it("decides a 16 MB attachment next to 32 MB of text in bounded time", () => {
    const args: Record<string, unknown> = { buffer: `data:image/png;base64,${"AAEC".repeat((16 << 20) / 4)}` };
    for (let i = 0; i < 1000; i++) args[`field${i}`] = `${i}:${"z".repeat(32 * 1024)}`;
    const start = performance.now();
    expect(fitInspectBody({ tool: "message", args }).refused).toBe(MESSAGE_TEXT_OVER_LIMIT);
    const photo = performance.now();
    expect(fitInspectBody({ tool: "message", args: { message: "hi", buffer: b64(noise(12 << 20)) } }).partial).toBe(true);
    expect(photo - start).toBeLessThan(5000);
    expect(performance.now() - photo).toBeLessThan(5000);
  });

  // A fixed-seed fuzz: random shapes of text, numbers and attachments, nested.
  // Every result is whole, refused, or partial within the limit with every
  // string but an attachment exactly as it was.
  const FUZZ_ATTACHMENTS = [4000, 60_000, 400_000, 900_000].map((n) => b64(noise(n)));
  it.each([1, 2, 3, 5, 8, 13, 21, 34, 55, 89])("never cuts text, fuzz seed %i", (seed) => {
    let state = (seed * 2654435761) >>> 0;
    const next = (n: number) => {
      state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
      return state % n;
    };
    const value = (depth: number): unknown => {
      const kind = next(depth > 3 ? 2 : 4);
      if (kind === 0) return "s".repeat(next(4) === 0 ? 1000 + next(100_000) : next(200));
      if (kind === 1) return next(1000);
      if (kind === 2) return Array.from({ length: next(40) }, () => value(depth + 1));
      return Object.fromEntries(Array.from({ length: next(40) }, (_, i) => [`k${i}`, value(depth + 1)]));
    };
    // Attachments (a few, shared, so the fuzz stays small in memory) sit beside the items, nested or not.
    const attachment = () => (next(3) === 0 ? { buffer: FUZZ_ATTACHMENTS[next(FUZZ_ATTACHMENTS.length)] } : { media: "short" });
    const payload = { tool: "message", args: {
      items: Array.from({ length: 30 + next(120) }, () => value(0)),
      attachments: Array.from({ length: next(8) }, attachment),
      buffer: next(2) === 0 ? FUZZ_ATTACHMENTS[next(FUZZ_ATTACHMENTS.length)] : "short",
    } };
    const before = JSON.stringify(payload);
    const got = fitInspectBody(payload);
    expect(JSON.stringify(payload)).toBe(before);
    if (bodyBytes(payload) <= LIMIT) {
      expect(got.payload).toBe(payload);
      return;
    }
    if (got.refused) return;
    expect(got.partial).toBe(true);
    expect(bodyBytes(got.payload)).toBeLessThanOrEqual(LIMIT);
    const strip = (v: unknown, key = ""): unknown =>
      typeof v === "string" ? ((key === "buffer" || key === "media") && v.length >= 4096 ? "ATTACHMENT" : v.startsWith("[attachment bytes not sent") ? "ATTACHMENT" : v)
        : Array.isArray(v) ? v.map((x) => strip(x))
          : v && typeof v === "object" ? Object.fromEntries(Object.entries(v).map(([k, x]) => [k, strip(x, k)]))
            : v;
    expect(strip(got.payload.args)).toEqual(strip(payload.args));
  });
});

// GAP-0436, round 5: a call whose body is over the old cut target (the limit
// less 1 KiB) by a few bytes and under the gateway's limit is sent whole: rel
// read these calls whole (its body is the params plus a copy of the text) and
// blocked the key in them. The shapes are the review's band shapes; the Go side
// (TestInspectToolMessageMarginBandStillBlocksTheKey) builds the same bytes and
// reads them through the gateway.
describe("fitInspectBody margin band (GAP-0436)", () => {
  const BAND = LIMIT - 1024;
  const keyText = `${prose(7000)} key: ${KEY} ${prose(7000)}`;

  // The call whose JSON is exactly `target` bytes: `coarse(n)` grows with n; a list of small numbers fills the rest.
  const exact = (target: number, coarse: (n: number) => Record<string, unknown>, most: number): Record<string, unknown> => {
    const sized = (n: number, pad: number[]) => bodyBytes(wrap({ ...coarse(n), pad }));
    let lo = 0;
    let hi = most;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (sized(mid, []) <= target - 4) lo = mid;
      else hi = mid - 1;
    }
    let count = 0;
    let top = target;
    while (count < top) {
      const mid = (count + top + 1) >> 1;
      if (sized(lo, new Array<number>(mid).fill(0)) <= target) count = mid;
      else top = mid - 1;
    }
    const pad = new Array<number>(count).fill(0);
    for (let i = 0; i < target - sized(lo, pad); i++) pad[i] = 10;
    expect(sized(lo, pad)).toBe(target);
    return { ...coarse(lo), pad };
  };

  const shapes: Array<[string, number, number, (n: number) => Record<string, unknown>]> = [
    ["band-body-numtable-1b", 1, 30_000, (n) => ({ action: "send", to: "+15550001111", body: keyText, presentation: { blocks: [{ type: "table", rows: rows(n) }] } })],
    ["band-body-numtable", 100, 30_000, (n) => ({ action: "send", to: "+15550001111", body: keyText, presentation: { blocks: [{ type: "table", rows: rows(n) }] } })],
    ["band-content-numtable", 100, 30_000, (n) => ({ action: "send", to: "+15550001111", content: keyText, presentation: { blocks: [{ type: "table", rows: rows(n) }] } })],
    ["band-body-short", 200, 20_000, (n) => ({ action: "send", to: "+15550001111", body: keyText, notes: Array.from({ length: n }, () => "y".repeat(100)) })],
    ["band-body-eqstrings", 150, 100, (n) => ({ action: "send", to: "+15550001111", body: keyText, ...Object.fromEntries(Array.from({ length: n }, (_, i) => [`f${i}`, "y".repeat(keyText.length)])) })],
  ];

  it.each(shapes)("%s is sent whole", (_name, over, most, coarse) => {
    const payload = wrap(exact(BAND + over, coarse, most));
    expect(bodyBytes(payload)).toBe(BAND + over);
    expect(bodyBytes(payload)).toBeLessThanOrEqual(GATEWAY_BODY_LIMIT_BYTES);
    const got = fitInspectBody(payload);
    expect(got.partial).toBe(false);
    expect(got.payload).toBe(payload);
    expect(got.payload).not.toHaveProperty("args_partial");
  });
});
