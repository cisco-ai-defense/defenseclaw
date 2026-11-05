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
 * Listener proof (GAP-0594). Before the plugin sends the DefenseClaw gateway
 * token or a provider key to the gateway API or the guardrail proxy, the
 * listener on that loopback port proves it holds the same token: the plugin
 * sends the token's SHA-256 and a fresh nonce to /api/v1/hook-listener-proof
 * and checks the HMAC-SHA256 under the token over
 * "defenseclaw.listener-proof.v1" NUL "openclaw" NUL nonce, the challenge
 * the Amp and OpenCode plugins use. The gateway answers only callers of its
 * own OS account, so a process of another account that holds the port while
 * the gateway restarts gets the digest and the nonce, never the token.
 *
 * Two forms:
 *  - provenCreateConnection(): proves the very TCP connection a node:http
 *    request then uses. The tool check, every DaemonClient call and the
 *    http(s).request proxy hop use it: nothing is written on a connection
 *    that has not proven itself.
 *  - proveListener(): proves the listener right before one fetch or undici
 *    dispatcher request, which cannot pick its connection. Nothing is
 *    reused; requests made while a proof is in flight share it. The residual
 *    is the gap between the proof and the request (sub-millisecond on
 *    loopback), the ENTERPRISE-THREAT-MODEL B7 / R7 class.
 */

import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { request as httpRequest } from "node:http";
import { connect as netConnect, type Socket } from "node:net";

export const LISTENER_PROOF_PATH = "/api/v1/hook-listener-proof";
const LISTENER_PROOF_DOMAIN = "defenseclaw.listener-proof.v1";
const LISTENER_PROOF_CONNECTOR = "openclaw";
/** A proof on loopback takes well under a millisecond; it never uses a call's budget. */
const LISTENER_PROOF_TIMEOUT_MS = 500;
const MAX_PROOF_RESPONSE_BYTES = 16 * 1024;

export class ListenerProofError extends Error {
  readonly code = "DC_PEER_UNVERIFIED";
  constructor(message: string) {
    super(message);
    this.name = "ListenerProofError";
  }
}

/** host as the plugin connects to it: localhost names the gateway's 127.0.0.1. */
export function canonicalLoopbackHost(host: string): string {
  const h = String(host || "").trim().replace(/^\[|\]$/g, "");
  return h.toLowerCase() === "localhost" ? "127.0.0.1" : h;
}

/** A loopback host name or address: 127.0.0.0/8, ::1 or localhost. */
export function isLoopbackHost(host: string): boolean {
  const h = String(host || "").trim().toLowerCase().replace(/^\[|\]$/g, "");
  if (h === "localhost" || h === "::1") return true;
  const m = /^127\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(h);
  return m !== null && m.slice(1).every((part) => Number(part) <= 255);
}

function checkTarget(host: string, token: string): void {
  if (!isLoopbackHost(host)) {
    throw new ListenerProofError(
      `DefenseClaw sends its gateway token only to a loopback listener; gateway.host ${host} is not one`,
    );
  }
  // A test proof (the other suites run without a gateway or token) stands in
  // for the token check too; the loopback rule always holds.
  if (!token && !proofOverride) {
    throw new ListenerProofError("no DefenseClaw gateway token to prove the listener with");
  }
}

function proofHeaders(token: string, nonce: string): Record<string, string> {
  return {
    "X-DefenseClaw-Connector": LISTENER_PROOF_CONNECTOR,
    "X-DefenseClaw-Listener-Key-Id": createHash("sha256").update(token.trim()).digest("hex"),
    "X-DefenseClaw-Listener-Nonce": nonce,
  };
}

function proofMatches(token: string, nonce: string, status: number, proof: string): boolean {
  if (status !== 204 || !/^[0-9a-f]{64}$/.test(proof)) return false;
  const want = createHmac("sha256", token.trim())
    .update(`${LISTENER_PROOF_DOMAIN}\u0000${LISTENER_PROOF_CONNECTOR}\u0000${nonce}`)
    .digest("hex");
  return timingSafeEqual(Buffer.from(proof, "hex"), Buffer.from(want, "hex"));
}

const notProven = (host: string, port: number) =>
  new ListenerProofError(
    `the listener on ${host}:${port} did not prove it is this account's DefenseClaw gateway; nothing was sent to it`,
  );

type RequestImpl = typeof httpRequest;

/** One proof over a connection of its own. */
function proveOnce(host: string, port: number, token: string, requestImpl: RequestImpl): Promise<void> {
  const nonce = randomBytes(32).toString("hex");
  return new Promise((resolve, reject) => {
    const req = requestImpl(
      {
        hostname: host.replace(/^\[|\]$/g, ""),
        port,
        path: LISTENER_PROOF_PATH,
        method: "GET",
        headers: proofHeaders(token, nonce),
        agent: false,
        timeout: LISTENER_PROOF_TIMEOUT_MS,
      },
      (res) => {
        res.resume();
        const proof = String(res.headers["x-defenseclaw-listener-proof"] || "");
        if (proofMatches(token, nonce, res.statusCode ?? 0, proof)) resolve();
        else reject(notProven(host, port));
      },
    );
    req.on("timeout", () => req.destroy(notProven(host, port)));
    req.on("error", (err) =>
      reject(err instanceof ListenerProofError ? err : new ListenerProofError(`${notProven(host, port).message}: ${err.message}`)),
    );
    req.end();
  });
}

type ProofOverride = (host: string, port: number, token: string) => Promise<void>;
let proofOverride: ProofOverride | undefined;

/**
 * Replace the proof (tests): the plugin's other suites run without a
 * gateway. undefined restores the real proof.
 */
export function _setListenerProofForTest(fn: ProofOverride | undefined): void {
  proofOverride = fn;
  inflight.clear();
}

const inflight = new Map<string, { token: string; pending: Promise<void> }>();
const keyOf = (host: string, port: number) => `${host.toLowerCase()}:${port}`;

/**
 * Prove the listener on host:port right before one request that carries the
 * token or a provider key. No proof is reused once it has settled; callers
 * that ask while one is in flight share it. Throws ListenerProofError.
 */
export async function proveListener(
  host: string,
  port: number,
  token: string,
  requestImpl: RequestImpl = httpRequest,
): Promise<void> {
  checkTarget(host, token);
  host = canonicalLoopbackHost(host);
  if (proofOverride) return proofOverride(host, port, token);
  const key = keyOf(host, port);
  const current = inflight.get(key);
  if (current && current.token === token) return current.pending;
  const entry = { token, pending: proveOnce(host, port, token, requestImpl) };
  inflight.set(key, entry);
  const settle = () => {
    if (inflight.get(key) === entry) inflight.delete(key);
  };
  entry.pending.then(settle, settle);
  return entry.pending;
}

/** Prove an open socket by sending the proof request on it (HTTP/1.1 keep-alive). */
function proveSocket(socket: Socket, host: string, port: number, token: string): Promise<void> {
  const nonce = randomBytes(32).toString("hex");
  const lines = [`GET ${LISTENER_PROOF_PATH} HTTP/1.1`, `Host: ${host}:${port}`, "Connection: keep-alive"];
  for (const [name, value] of Object.entries(proofHeaders(token, nonce))) lines.push(`${name}: ${value}`);
  return new Promise((resolve, reject) => {
    let buf = Buffer.alloc(0);
    const timer = setTimeout(() => finish(notProven(host, port)), LISTENER_PROOF_TIMEOUT_MS);
    const finish = (err?: Error) => {
      clearTimeout(timer);
      socket.removeListener("data", onData);
      socket.removeListener("error", onError);
      socket.removeListener("close", onClose);
      if (err) reject(err);
      else resolve();
    };
    const onError = (err: Error) => finish(new ListenerProofError(`${notProven(host, port).message}: ${err.message}`));
    const onClose = () => finish(notProven(host, port));
    const onData = (chunk: Buffer) => {
      buf = Buffer.concat([buf, chunk]);
      const end = buf.indexOf("\r\n\r\n");
      if (end < 0) {
        if (buf.length > MAX_PROOF_RESPONSE_BYTES) finish(notProven(host, port));
        return;
      }
      // A 204 has no body: any byte after the head is not a proof answer.
      if (buf.length !== end + 4) return finish(notProven(host, port));
      const head = buf.subarray(0, end).toString("latin1").split("\r\n");
      const status = Number(/^HTTP\/1\.1 (\d{3}) /.exec(head[0] + " ")?.[1] ?? 0);
      let proof = "";
      for (const line of head.slice(1)) {
        const colon = line.indexOf(":");
        if (colon > 0 && line.slice(0, colon).trim().toLowerCase() === "x-defenseclaw-listener-proof") {
          proof = line.slice(colon + 1).trim();
        }
      }
      finish(proofMatches(token, nonce, status, proof) ? undefined : notProven(host, port));
    };
    socket.on("data", onData);
    socket.on("error", onError);
    socket.on("close", onClose);
    socket.write(lines.join("\r\n") + "\r\n\r\n");
  });
}

type CreateConnection = (
  options: { host?: string | null; hostname?: string | null; port?: number | string | null },
  oncreate: (err: Error | null, socket?: Socket) => void,
) => undefined;

/**
 * A node:http createConnection that proves the TCP connection before the
 * request is written on it. node:http uses it only when the request has no
 * agent (agent undefined, not false). The connect is bounded by
 * LISTENER_PROOF_TIMEOUT_MS, as the proof is: a listener that never accepts
 * (a wedged gateway, a full accept queue, a squatter that never calls
 * accept) fails the request at once instead of after the kernel's connect
 * timeout of about two minutes. connectImpl is replaceable in tests.
 */
export function provenCreateConnection(
  host: string,
  port: number,
  token: string,
  connectImpl: (options: { host: string; port: number }) => Socket = netConnect,
): CreateConnection {
  return (_options, oncreate) => {
    try {
      checkTarget(host, token);
    } catch (err) {
      process.nextTick(() => oncreate(err as Error));
      return undefined;
    }
    let done = false;
    const once = (err: Error | null, socket?: Socket) => {
      if (done) return;
      done = true;
      oncreate(err, socket);
    };
    const address = canonicalLoopbackHost(host);
    const socket = connectImpl({ host: address, port });
    const prove = proofOverride
      ? () => proofOverride!(host, port, token)
      : () => proveSocket(socket, address, port, token);
    const connectTimer = setTimeout(() => {
      socket.removeListener("error", onConnectError);
      socket.destroy();
      once(new ListenerProofError(`${notProven(host, port).message}: connect timed out`));
    }, LISTENER_PROOF_TIMEOUT_MS);
    const onConnectError = (err: Error) => {
      clearTimeout(connectTimer);
      once(new ListenerProofError(`${notProven(host, port).message}: ${err.message}`));
    };
    socket.once("error", onConnectError);
    socket.once("connect", () => {
      clearTimeout(connectTimer);
      socket.removeListener("error", onConnectError);
      prove().then(
        () => once(null, socket),
        (err) => {
          socket.destroy();
          once(err);
        },
      );
    });
    return undefined;
  };
}
