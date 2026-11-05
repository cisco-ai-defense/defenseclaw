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
 *  - proveListener(): a proof per host:port, cached for
 *    LISTENER_PROOF_REFRESH_MS and dropped after a connection error, for
 *    fetch and dispatcher calls that cannot pick their connection.
 *  - provenCreateConnection(): proves the very TCP connection a node:http
 *    request then uses, for the requests that open their own connection.
 */

import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { request as httpRequest } from "node:http";
import { connect as netConnect, type Socket } from "node:net";

export const LISTENER_PROOF_PATH = "/api/v1/hook-listener-proof";
const LISTENER_PROOF_DOMAIN = "defenseclaw.listener-proof.v1";
const LISTENER_PROOF_CONNECTOR = "openclaw";
/** A cached proof is used for this long, then proven again before use. */
export const LISTENER_PROOF_REFRESH_MS = 2_000;
const LISTENER_PROOF_TIMEOUT_MS = 2_000;
const MAX_PROOF_RESPONSE_BYTES = 16 * 1024;

export class ListenerProofError extends Error {
  readonly code = "DC_PEER_UNVERIFIED";
  constructor(message: string) {
    super(message);
    this.name = "ListenerProofError";
  }
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
  if (!token) {
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

interface ProofEntry {
  token: string;
  provenAt: number;
  pending?: Promise<void>;
}

const proofs = new Map<string, ProofEntry>();

type ProofOverride = (host: string, port: number, token: string) => Promise<void>;
let proofOverride: ProofOverride | undefined;

/**
 * Replace the proof (tests): the plugin's other suites run without a
 * gateway. undefined restores the real proof.
 */
export function _setListenerProofForTest(fn: ProofOverride | undefined): void {
  proofOverride = fn;
  proofs.clear();
}
const keyOf = (host: string, port: number) => `${host.toLowerCase()}:${port}`;

/**
 * Prove the listener on host:port before a request that carries the token
 * or a provider key. A proof younger than LISTENER_PROOF_REFRESH_MS is
 * reused; concurrent callers share one proof. Throws ListenerProofError.
 */
export async function proveListener(
  host: string,
  port: number,
  token: string,
  requestImpl: RequestImpl = httpRequest,
  now: () => number = Date.now,
): Promise<void> {
  checkTarget(host, token);
  if (proofOverride) return proofOverride(host, port, token);
  const key = keyOf(host, port);
  const entry = proofs.get(key);
  if (entry && entry.token === token) {
    if (entry.provenAt > 0 && now() - entry.provenAt < LISTENER_PROOF_REFRESH_MS) return;
    if (entry.pending) return entry.pending;
  }
  const pending = proveOnce(host, port, token, requestImpl).then(
    () => {
      proofs.set(key, { token, provenAt: now() });
    },
    (err) => {
      proofs.delete(key);
      throw err;
    },
  );
  proofs.set(key, { token, provenAt: 0, pending });
  return pending;
}

/** Whether host:port holds a proof for token younger than LISTENER_PROOF_REFRESH_MS. */
export function listenerProofFresh(host: string, port: number, token: string, now: () => number = Date.now): boolean {
  if (proofOverride) return isLoopbackHost(host) && token !== "";
  const entry = proofs.get(keyOf(host, port));
  return Boolean(entry && entry.token === token && entry.provenAt > 0 && now() - entry.provenAt < LISTENER_PROOF_REFRESH_MS);
}

/** Drop the proof of host:port, after a connection error to it. */
export function forgetListenerProof(host: string, port: number): void {
  proofs.delete(keyOf(host, port));
}

/** Clear every cached proof (tests). */
export function _resetListenerProofs(): void {
  proofs.clear();
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
 * agent (agent undefined, not false).
 */
export function provenCreateConnection(host: string, port: number, token: string): CreateConnection {
  return (_options, oncreate) => {
    try {
      checkTarget(host, token);
    } catch (err) {
      process.nextTick(() => oncreate(err as Error));
      return undefined;
    }
    const socket = netConnect({ host: host.replace(/^\[|\]$/g, ""), port });
    const prove = proofOverride
      ? () => proofOverride!(host, port, token)
      : () => proveSocket(socket, host, port, token);
    const onConnectError = (err: Error) => oncreate(new ListenerProofError(`${notProven(host, port).message}: ${err.message}`));
    socket.once("error", onConnectError);
    socket.once("connect", () => {
      socket.removeListener("error", onConnectError);
      prove().then(
        () => oncreate(null, socket),
        (err) => {
          socket.destroy();
          oncreate(err);
        },
      );
    });
    return undefined;
  };
}
