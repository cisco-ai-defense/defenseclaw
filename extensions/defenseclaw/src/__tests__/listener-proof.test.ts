/**
 * Copyright 2026 Cisco Systems, Inc. and its affiliates
 * SPDX-License-Identifier: Apache-2.0
 */

import { createHmac } from "node:crypto";
import { createServer, request, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  ListenerProofError,
  LISTENER_PROOF_PATH,
  _setListenerProofForTest,
  forgetListenerProof,
  isLoopbackHost,
  listenerProofFresh,
  proveListener,
  provenCreateConnection,
} from "../listener-proof.js";
import { DaemonClient } from "../client.js";

const TOKEN = "a".repeat(64);

interface Seen {
  proofs: number;
  authorized: string[];
  remotePorts: number[];
}

/** A loopback server that answers the proof under key (or wrongly). */
async function listener(key: string | null): Promise<{ server: Server; port: number; seen: Seen }> {
  const seen: Seen = { proofs: 0, authorized: [], remotePorts: [] };
  const server = createServer((req: IncomingMessage, res: ServerResponse) => {
    seen.remotePorts.push(req.socket.remotePort ?? 0);
    if (req.url === LISTENER_PROOF_PATH) {
      seen.proofs++;
      const nonce = String(req.headers["x-defenseclaw-listener-nonce"] || "");
      if (key === null) {
        res.writeHead(401).end();
        return;
      }
      const proof = createHmac("sha256", key)
        .update(`defenseclaw.listener-proof.v1\u0000${String(req.headers["x-defenseclaw-connector"])}\u0000${nonce}`)
        .digest("hex");
      res.writeHead(204, { "X-DefenseClaw-Listener-Proof": proof }).end();
      return;
    }
    if (req.headers.authorization) seen.authorized.push(String(req.headers.authorization));
    res.writeHead(200, { "Content-Type": "application/json" }).end("{}");
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  return { server, port: (server.address() as AddressInfo).port, seen };
}

const servers: Server[] = [];

beforeEach(() => _setListenerProofForTest(undefined));
afterEach(async () => {
  _setListenerProofForTest(async () => {});
  await Promise.all(servers.splice(0).map((s) => new Promise((r) => s.close(r))));
});

describe("listener proof (GAP-0594)", () => {
  it("accepts loopback hosts only", () => {
    expect(isLoopbackHost("127.0.0.1")).toBe(true);
    expect(isLoopbackHost("127.1.2.3")).toBe(true);
    expect(isLoopbackHost("::1")).toBe(true);
    expect(isLoopbackHost("[::1]")).toBe(true);
    expect(isLoopbackHost("localhost")).toBe(true);
    expect(isLoopbackHost("10.0.0.5")).toBe(false);
    expect(isLoopbackHost("gateway.example.com")).toBe(false);
    expect(isLoopbackHost("127.0.0.256")).toBe(false);
  });

  it("proves this account's gateway once and reuses the proof", async () => {
    const { server, port, seen } = await listener(TOKEN);
    servers.push(server);
    await proveListener("127.0.0.1", port, TOKEN);
    await proveListener("127.0.0.1", port, TOKEN);
    expect(seen.proofs).toBe(1);
    expect(listenerProofFresh("127.0.0.1", port, TOKEN)).toBe(true);
    forgetListenerProof("127.0.0.1", port);
    expect(listenerProofFresh("127.0.0.1", port, TOKEN)).toBe(false);
    await proveListener("127.0.0.1", port, TOKEN);
    expect(seen.proofs).toBe(2);
  });

  it("proves again once the proof is older than the refresh window", async () => {
    const { server, port, seen } = await listener(TOKEN);
    servers.push(server);
    let clock = 1_000_000;
    await proveListener("127.0.0.1", port, TOKEN, request, () => clock);
    clock += 60_000;
    await proveListener("127.0.0.1", port, TOKEN, request, () => clock);
    expect(seen.proofs).toBe(2);
  });

  it("refuses a listener that cannot prove the token", async () => {
    for (const key of [null, "b".repeat(64)]) {
      const { server, port } = await listener(key);
      servers.push(server);
      await expect(proveListener("127.0.0.1", port, TOKEN)).rejects.toBeInstanceOf(ListenerProofError);
      expect(listenerProofFresh("127.0.0.1", port, TOKEN)).toBe(false);
    }
  });

  it("never contacts a non-loopback gateway.host", async () => {
    await expect(proveListener("192.0.2.10", 18970, TOKEN)).rejects.toThrow(/loopback/);
  });

  it("proves the connection a request then uses, before its headers", async () => {
    const { server, port, seen } = await listener(TOKEN);
    servers.push(server);
    const status = await new Promise<number>((resolve, reject) => {
      const req = request(
        {
          hostname: "127.0.0.1",
          port,
          path: "/status",
          headers: { Authorization: `Bearer ${TOKEN}` },
          createConnection: provenCreateConnection("127.0.0.1", port, TOKEN) as never,
        },
        (res) => {
          res.resume();
          resolve(res.statusCode ?? 0);
        },
      );
      req.on("error", reject);
      req.end();
    });
    expect(status).toBe(200);
    expect(seen.proofs).toBe(1);
    expect(seen.authorized).toEqual([`Bearer ${TOKEN}`]);
    expect(new Set(seen.remotePorts).size).toBe(1);
  });

  it("writes no token on a connection that failed the proof", async () => {
    const { server, port, seen } = await listener("b".repeat(64));
    servers.push(server);
    const err = await new Promise<Error>((resolve) => {
      const req = request(
        {
          hostname: "127.0.0.1",
          port,
          path: "/status",
          headers: { Authorization: `Bearer ${TOKEN}` },
          createConnection: provenCreateConnection("127.0.0.1", port, TOKEN) as never,
        },
        () => resolve(new Error("answered")),
      );
      req.on("error", resolve);
      req.end();
    });
    expect(err).toBeInstanceOf(ListenerProofError);
    expect(seen.authorized).toEqual([]);
  });

  it("DaemonClient sends no token to a listener that cannot prove it", async () => {
    const { server, port, seen } = await listener("b".repeat(64));
    servers.push(server);
    const client = new DaemonClient({ baseUrl: `http://127.0.0.1:${port}`, token: TOKEN });
    const res = await client.status();
    expect(res.ok).toBe(false);
    expect(res.status).toBe(0);
    expect(seen.authorized).toEqual([]);
    await expect(client.buildOutboundHeaders()).rejects.toBeInstanceOf(ListenerProofError);
  });

  it("DaemonClient sends the token to this account's gateway", async () => {
    const { server, port, seen } = await listener(TOKEN);
    servers.push(server);
    const client = new DaemonClient({ baseUrl: `http://127.0.0.1:${port}`, token: TOKEN });
    const res = await client.status();
    expect(res.ok).toBe(true);
    expect(seen.authorized).toEqual([`Bearer ${TOKEN}`]);
    const headers = await client.buildOutboundHeaders();
    expect(headers.Authorization).toBe(`Bearer ${TOKEN}`);
  });
});
