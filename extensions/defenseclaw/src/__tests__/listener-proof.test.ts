/**
 * Copyright 2026 Cisco Systems, Inc. and its affiliates
 * SPDX-License-Identifier: Apache-2.0
 */

import { createHmac } from "node:crypto";
import { execFile } from "node:child_process";
import { createServer, request, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { Socket, createServer as createNetServer, type AddressInfo } from "node:net";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  ListenerProofError,
  LISTENER_PROOF_PATH,
  _setListenerProofForTest,
  canonicalLoopbackHost,
  isLoopbackHost,
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

  it("proves the listener again for every request (no reuse)", async () => {
    const { server, port, seen } = await listener(TOKEN);
    servers.push(server);
    await proveListener("127.0.0.1", port, TOKEN);
    await proveListener("127.0.0.1", port, TOKEN);
    expect(seen.proofs).toBe(2);
  });

  it("shares only a proof that is still in flight", async () => {
    const { server, port, seen } = await listener(TOKEN);
    servers.push(server);
    await Promise.all([proveListener("127.0.0.1", port, TOKEN), proveListener("127.0.0.1", port, TOKEN)]);
    expect(seen.proofs).toBe(1);
    await proveListener("127.0.0.1", port, TOKEN);
    expect(seen.proofs).toBe(2);
  });

  it("sends nothing to a listener that replaced the gateway after a good proof", async () => {
    const good = await listener(TOKEN);
    const port = good.port;
    const client = new DaemonClient({ baseUrl: `http://127.0.0.1:${port}`, token: TOKEN });
    expect((await client.listBlocked()).ok).toBe(true);
    await proveListener("127.0.0.1", port, TOKEN);
    await new Promise((r) => good.server.close(r));

    // Another account's process takes the port while the gateway restarts.
    const seen: Seen = { proofs: 0, authorized: [], remotePorts: [] };
    const others: string[] = [];
    const squatter = createServer((req, res) => {
      if (req.url === LISTENER_PROOF_PATH && req.method === "GET") {
        seen.proofs++;
        res.writeHead(401).end();
        return;
      }
      // Any other request reached the squatter: record it whatever it carries.
      others.push(`${req.method} ${req.url} auth=${req.headers.authorization ? "yes" : "no"}`);
      if (req.headers.authorization) seen.authorized.push(String(req.headers.authorization));
      res.writeHead(200, { "Content-Type": "application/json" }).end(JSON.stringify({ action: "allow" }));
    });
    await new Promise<void>((resolve) => squatter.listen(port, "127.0.0.1", resolve));
    servers.push(squatter);

    const res = await client.postRaw("/api/v1/inspect/tool", { tool: "exec" });
    expect(res.status).toBe(0);
    await expect(proveListener("127.0.0.1", port, TOKEN)).rejects.toBeInstanceOf(ListenerProofError);
    await expect(client.buildOutboundHeaders()).rejects.toBeInstanceOf(ListenerProofError);
    expect(seen.proofs).toBe(3);
    expect(seen.authorized).toEqual([]);
    expect(others).toEqual([]);
  });

  it("fails a connection that never comes up at the shared deadline", async () => {
    const stalled = new Socket();
    const started = Date.now();
    const err = await new Promise<Error | null>((resolve) => {
      provenCreateConnection("127.0.0.1", 9, TOKEN, () => stalled, 300)({}, (e) => resolve(e));
    });
    expect(err).toBeInstanceOf(ListenerProofError);
    expect(String(err?.message)).toContain("connect timed out");
    expect(Date.now() - started).toBeLessThan(1_500);
    expect(stalled.destroyed).toBe(true);
  });

  it("expires the deadline in a quiet process, with no other event to wake the loop", async () => {
    // Inside vitest the runner wakes the loop on its own; a child process
    // whose only other wake-up is a timer far past the deadline shows whether
    // the deadline fires by itself. It once waited for that next event.
    const deadlineMs = 200;
    const wakeMs = 10_000;
    const child = `
      const net = await import("node:net");
      const { provenCreateConnection } = await import(process.argv[1]);
      const late = setTimeout(() => { console.log(JSON.stringify({ late: true })); process.exit(0); }, ${wakeMs});
      const run = (impl, port) => new Promise((resolve) => {
        const t0 = Date.now();
        provenCreateConnection("127.0.0.1", port, "${TOKEN}", impl, ${deadlineMs})({}, (e) =>
          resolve({ ms: Date.now() - t0, msg: String(e && e.message) }));
      });
      const stalled = new net.Socket();
      const connect = await run(() => stalled, 9);
      const mute = net.createServer(() => {});
      await new Promise((r) => mute.listen(0, "127.0.0.1", r));
      const proof = await run(net.connect, mute.address().port);
      clearTimeout(late);
      console.log(JSON.stringify({ connect, proof, destroyed: stalled.destroyed }));
      process.exit(0);
    `;
    const src = new URL("../listener-proof.ts", import.meta.url).href;
    const out = await new Promise<string>((resolve, reject) => {
      execFile(
        process.execPath,
        ["--experimental-strip-types", "--no-warnings", "--input-type=module", "-e", child, src],
        { timeout: wakeMs * 2 },
        (err, stdout, stderr) => (err ? reject(new Error(`${err.message}\n${stderr}`)) : resolve(stdout)),
      );
    });
    const got = JSON.parse(out.trim().split("\n").pop() ?? "{}");
    expect(got.late).toBeUndefined();
    expect(got.connect.msg).toContain("connect timed out");
    expect(got.proof.msg).toContain("did not prove");
    // Bounded by the deadline, far ahead of the next unrelated wake-up.
    expect(got.connect.ms).toBeGreaterThanOrEqual(deadlineMs - 5);
    expect(got.connect.ms).toBeLessThan(wakeMs / 4);
    expect(got.proof.ms).toBeLessThan(wakeMs / 4);
    expect(got.destroyed).toBe(true);
  }, 30_000);

  it("keeps a proof whose answer arrives after a 700 ms event-loop stall (R3-M1)", async () => {
    const { server, port, seen } = await listener(TOKEN);
    servers.push(server);
    const result = new Promise<Error | null>((resolve) => {
      provenCreateConnection("127.0.0.1", port, TOKEN)({}, (e, socket) => {
        socket?.destroy();
        resolve(e);
      });
    });
    // OpenClaw's main thread is busy (a large session, a GC pause).
    const until = Date.now() + 700;
    while (Date.now() < until) {
      // block
    }
    expect(await result).toBeNull();
    expect(seen.proofs).toBe(1);
  });

  it("keeps a fetch-path proof across a 700 ms event-loop stall", async () => {
    const { server, port, seen } = await listener(TOKEN);
    servers.push(server);
    const proof = proveListener("127.0.0.1", port, TOKEN);
    const until = Date.now() + 700;
    while (Date.now() < until) {
      // block
    }
    await expect(proof).resolves.toBeUndefined();
    expect(seen.proofs).toBe(1);
  });

  it("reports a body cut off mid-response as no answer", async () => {
    const server = createServer((req, res) => {
      if (req.url === LISTENER_PROOF_PATH) {
        const nonce = String(req.headers["x-defenseclaw-listener-nonce"] || "");
        const proof = createHmac("sha256", TOKEN)
          .update(`defenseclaw.listener-proof.v1\u0000openclaw\u0000${nonce}`)
          .digest("hex");
        res.writeHead(204, { "X-DefenseClaw-Listener-Proof": proof }).end();
        return;
      }
      res.writeHead(200, { "Content-Type": "application/json", "Content-Length": "200" });
      res.write('{"action":"allow",');
      setTimeout(() => req.socket.destroy(), 20);
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    servers.push(server);
    const port = (server.address() as AddressInfo).port;
    const client = new DaemonClient({ baseUrl: `http://127.0.0.1:${port}`, token: TOKEN });
    const res = await client.postRaw("/api/v1/inspect/tool", { tool: "exec" });
    expect(res.status).toBe(0);
  });

  it("names localhost as the 127.0.0.1 the gateway binds", async () => {
    expect(canonicalLoopbackHost("localhost")).toBe("127.0.0.1");
    expect(canonicalLoopbackHost("[::1]")).toBe("::1");
    const { server, port, seen } = await listener(TOKEN);
    servers.push(server);
    await proveListener("localhost", port, TOKEN);
    expect(seen.proofs).toBe(1);
  });

  it("sends nothing without a token to prove with", async () => {
    const { server, port, seen } = await listener(TOKEN);
    servers.push(server);
    const client = new DaemonClient({ baseUrl: `http://127.0.0.1:${port}`, token: "" });
    const res = await client.postRaw("/api/v1/inspect/tool", { tool: "exec" });
    expect(res.status).toBe(0);
    expect(seen.remotePorts).toEqual([]);
  });

  it("refuses a listener that cannot prove the token", async () => {
    for (const key of [null, "b".repeat(64)]) {
      const { server, port } = await listener(key);
      servers.push(server);
      await expect(proveListener("127.0.0.1", port, TOKEN)).rejects.toBeInstanceOf(ListenerProofError);
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
    const res = await client.listBlocked();
    expect(res.ok).toBe(false);
    expect(res.status).toBe(0);
    expect(seen.authorized).toEqual([]);
    await expect(client.buildOutboundHeaders()).rejects.toBeInstanceOf(ListenerProofError);
  });

  it("DaemonClient sends the token to this account's gateway", async () => {
    const { server, port, seen } = await listener(TOKEN);
    servers.push(server);
    const client = new DaemonClient({ baseUrl: `http://127.0.0.1:${port}`, token: TOKEN });
    const res = await client.listBlocked();
    expect(res.ok).toBe(true);
    expect(seen.authorized).toEqual([`Bearer ${TOKEN}`]);
    const headers = await client.buildOutboundHeaders();
    expect(headers.Authorization).toBe(`Bearer ${TOKEN}`);
  });
});

// GAP-0600 with GAP-0594: the plugin applies the saved outage mode to a tool
// check only when the gateway did not answer. A listener that answered
// without a valid proof is not an outage and is blocked in every tier.
describe("outage classification of a check that got no answer", () => {
  const closedPort = async (): Promise<number> => {
    const probe = createServer();
    await new Promise<void>((resolve) => probe.listen(0, "127.0.0.1", resolve));
    const port = (probe.address() as AddressInfo).port;
    await new Promise((resolve) => probe.close(resolve));
    return port;
  };

  /** A listener that proves itself, then handles the check with onCheck. */
  async function provenGateway(onCheck: (req: IncomingMessage, res: ServerResponse) => void): Promise<number> {
    const server = createServer((req, res) => {
      if (req.url === LISTENER_PROOF_PATH) {
        const nonce = String(req.headers["x-defenseclaw-listener-nonce"] || "");
        const proof = createHmac("sha256", TOKEN)
          .update(`defenseclaw.listener-proof.v1\u0000openclaw\u0000${nonce}`)
          .digest("hex");
        res.writeHead(204, { "X-DefenseClaw-Listener-Proof": proof }).end();
        return;
      }
      onCheck(req, res);
    });
    const sockets = new Set<Socket>();
    server.on("connection", (socket) => {
      sockets.add(socket);
      socket.on("close", () => sockets.delete(socket));
    });
    const close = server.close.bind(server);
    server.close = ((cb?: (err?: Error) => void) => {
      for (const socket of sockets) socket.destroy();
      return close(cb);
    }) as typeof server.close;
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    servers.push(server);
    return (server.address() as AddressInfo).port;
  }

  it("reports nothing listening on the gateway port as an outage", async () => {
    const port = await closedPort();
    const client = new DaemonClient({ baseUrl: `http://127.0.0.1:${port}`, token: TOKEN });
    const res = await client.postRaw("/api/v1/inspect/tool", { tool: "exec" });
    expect(res.status).toBe(0);
    expect(res.outage).toBe(true);
    const err = await proveListener("127.0.0.1", port, TOKEN).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ListenerProofError);
    expect((err as ListenerProofError).unreachable).toBe(true);
  });

  it("reports a listener that never answers the proof as an outage", async () => {
    const accepted: Socket[] = [];
    const mute = createNetServer((socket) => {
      accepted.push(socket);
    });
    await new Promise<void>((resolve) => mute.listen(0, "127.0.0.1", resolve));
    try {
      const port = (mute.address() as AddressInfo).port;
      const err = await new Promise<Error | null>((resolve) => {
        provenCreateConnection("127.0.0.1", port, TOKEN, undefined, 200)({}, (e) => resolve(e));
      });
      expect(err).toBeInstanceOf(ListenerProofError);
      expect((err as ListenerProofError).unreachable).toBe(true);
      const stalled = new Socket();
      const connectErr = await new Promise<Error | null>((resolve) => {
        provenCreateConnection("127.0.0.1", 9, TOKEN, () => stalled, 200)({}, (e) => resolve(e));
      });
      expect((connectErr as ListenerProofError).unreachable).toBe(true);
    } finally {
      for (const socket of accepted) socket.destroy();
      await new Promise((resolve) => mute.close(resolve));
    }
  });

  it("never reports a listener that fails the proof as an outage, and sends it nothing", async () => {
    for (const key of [null, "b".repeat(64)]) {
      const { server, port, seen } = await listener(key);
      servers.push(server);
      const client = new DaemonClient({ baseUrl: `http://127.0.0.1:${port}`, token: TOKEN });
      const res = await client.postRaw("/api/v1/inspect/tool", { tool: "exec", args: { command: "date" } });
      expect(res.status).toBe(0);
      expect(res.outage).toBe(false);
      expect(seen.authorized).toEqual([]);
      const err = await proveListener("127.0.0.1", port, TOKEN).catch((e: unknown) => e);
      expect(err).toBeInstanceOf(ListenerProofError);
      expect((err as ListenerProofError).unreachable).toBe(false);
    }
  });

  it("never reports a missing token or a non-loopback gateway.host as an outage", async () => {
    const port = await closedPort();
    const noToken = new DaemonClient({ baseUrl: `http://127.0.0.1:${port}`, token: "" });
    const unsent = await noToken.postRaw("/api/v1/inspect/tool", { tool: "exec" });
    expect(unsent.status).toBe(0);
    expect(unsent.outage).toBe(false);
    const remote = new DaemonClient({ baseUrl: "http://192.0.2.10:18970", token: TOKEN });
    const refused = await remote.postRaw("/api/v1/inspect/tool", { tool: "exec" });
    expect(refused.status).toBe(0);
    expect(refused.outage).toBe(false);
  });

  it("reports a proven connection that breaks off, is cut off or times out as an outage", async () => {
    const reset = await provenGateway((req) => req.socket.destroy());
    const cut = await provenGateway((req, res) => {
      res.writeHead(200, { "Content-Type": "application/json", "Content-Length": "200" });
      res.write("{\"action\":\"allow\",");
      setTimeout(() => req.socket.destroy(), 20);
    });
    const silent = await provenGateway(() => undefined);
    for (const [port, timeoutMs] of [[reset, 2_000], [cut, 2_000], [silent, 200]]) {
      const client = new DaemonClient({ baseUrl: `http://127.0.0.1:${port}`, token: TOKEN });
      const res = await client.postRaw("/api/v1/inspect/tool", { tool: "exec" }, { timeoutMs });
      expect(res.status).toBe(0);
      expect(res.outage).toBe(true);
    }
  });
});

describe("listener proof outage wording (rel-1-0-10 GAP-0064)", () => {
  it("says the gateway is not running when nothing listens", async () => {
    _setListenerProofForTest(undefined);
    const err = await proveListener("127.0.0.1", 1, "a".repeat(64)).catch((e) => e);
    expect(err).toBeInstanceOf(ListenerProofError);
    expect(String(err.message)).toContain("the DefenseClaw gateway is not running");
    expect(String(err.message)).not.toContain("did not prove");
  });
});
