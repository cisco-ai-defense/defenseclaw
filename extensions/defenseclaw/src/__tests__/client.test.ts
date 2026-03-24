import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { createServer } from "node:http";
import type { Server, IncomingMessage, ServerResponse } from "node:http";
import { DaemonClient } from "../client.js";

let server: Server;
let port: number;
let lastRequest: {
  method: string;
  url: string;
  body: string;
  headers: Record<string, string | string[] | undefined>;
};

function resetLastRequest() {
  lastRequest = { method: "", url: "", body: "", headers: {} };
}

let responseOverride: {
  status: number;
  body: string;
} | null = null;

beforeAll(
  () =>
    new Promise<void>((resolve) => {
      server = createServer((req: IncomingMessage, res: ServerResponse) => {
        const chunks: Buffer[] = [];
        req.on("data", (c: Buffer) => chunks.push(c));
        req.on("end", () => {
          lastRequest = {
            method: req.method ?? "GET",
            url: req.url ?? "/",
            body: Buffer.concat(chunks).toString("utf-8"),
            headers: req.headers as Record<string, string | string[] | undefined>,
          };

          if (responseOverride) {
            res.writeHead(responseOverride.status, {
              "Content-Type": "application/json",
            });
            res.end(responseOverride.body);
            return;
          }

          res.writeHead(200, { "Content-Type": "application/json" });

          if (req.url === "/status") {
            res.end(JSON.stringify({ running: true, uptime_seconds: 42 }));
          } else if (req.url === "/enforce/blocked") {
            res.end(JSON.stringify([]));
          } else if (req.url === "/enforce/allowed") {
            res.end(JSON.stringify([]));
          } else if (req.url === "/skills") {
            res.end(JSON.stringify(["skill-a", "skill-b"]));
          } else if (req.url === "/mcps") {
            res.end(JSON.stringify(["mcp-a"]));
          } else if (req.url?.startsWith("/alerts")) {
            res.end(JSON.stringify([]));
          } else if (req.url === "/policy/evaluate" && req.method === "POST") {
            const payload = JSON.parse(
              Buffer.concat(chunks).toString("utf-8") || "{}",
            );
            res.end(
              JSON.stringify({
                ok: true,
                data: {
                  verdict: "clean",
                  reason: "test policy result",
                  domain: payload.domain,
                },
              }),
            );
          } else {
            res.end("{}");
          }
        });
      });

      server.listen(0, "127.0.0.1", () => {
        const addr = server.address();
        port = typeof addr === "object" && addr ? addr.port : 0;
        resolve();
      });
    }),
);

afterAll(
  () =>
    new Promise<void>((resolve) => {
      server.close(() => resolve());
    }),
);

function makeClient() {
  return new DaemonClient({ baseUrl: `http://127.0.0.1:${port}` });
}

describe("DaemonClient", () => {
  describe("status", () => {
    it("returns daemon status on success", async () => {
      resetLastRequest();
      responseOverride = null;
      const client = makeClient();
      const res = await client.status();

      expect(res.ok).toBe(true);
      expect(res.status).toBe(200);
      expect(res.data).toEqual({ running: true, uptime_seconds: 42 });
      expect(lastRequest.method).toBe("GET");
      expect(lastRequest.url).toBe("/status");
    });
  });

  describe("submitScanResult", () => {
    it("posts scan result to /scan/result", async () => {
      resetLastRequest();
      responseOverride = null;
      const client = makeClient();
      const scanResult = {
        scanner: "test",
        target: "/path",
        timestamp: "2025-01-01T00:00:00Z",
        findings: [],
      };

      const res = await client.submitScanResult(scanResult);

      expect(res.ok).toBe(true);
      expect(lastRequest.method).toBe("POST");
      expect(lastRequest.url).toBe("/scan/result");
      expect(JSON.parse(lastRequest.body)).toEqual(scanResult);
    });
  });

  describe("block", () => {
    it("posts block request with correct payload", async () => {
      resetLastRequest();
      responseOverride = null;
      const client = makeClient();
      await client.block("skill", "evil-skill", "contains malware");

      expect(lastRequest.method).toBe("POST");
      expect(lastRequest.url).toBe("/enforce/block");
      expect(JSON.parse(lastRequest.body)).toEqual({
        target_type: "skill",
        target_name: "evil-skill",
        reason: "contains malware",
      });
    });
  });

  describe("allow", () => {
    it("posts allow request with correct payload", async () => {
      resetLastRequest();
      responseOverride = null;
      const client = makeClient();
      await client.allow("mcp", "trusted-mcp", "reviewed and approved");

      expect(lastRequest.method).toBe("POST");
      expect(lastRequest.url).toBe("/enforce/allow");
      expect(JSON.parse(lastRequest.body)).toEqual({
        target_type: "mcp",
        target_name: "trusted-mcp",
        reason: "reviewed and approved",
      });
    });
  });

  describe("unblock", () => {
    it("sends DELETE to /enforce/block with JSON body", async () => {
      resetLastRequest();
      responseOverride = null;
      const client = makeClient();
      await client.unblock("skill", "temp-skill");

      expect(lastRequest.method).toBe("DELETE");
      expect(lastRequest.url).toBe("/enforce/block");
      expect(JSON.parse(lastRequest.body)).toEqual({
        target_type: "skill",
        target_name: "temp-skill",
      });
    });
  });

  describe("listSkills", () => {
    it("returns skill list", async () => {
      resetLastRequest();
      responseOverride = null;
      const client = makeClient();
      const res = await client.listSkills();

      expect(res.ok).toBe(true);
      expect(res.data).toEqual(["skill-a", "skill-b"]);
    });
  });

  describe("listMCPs", () => {
    it("returns MCP list", async () => {
      resetLastRequest();
      responseOverride = null;
      const client = makeClient();
      const res = await client.listMCPs();

      expect(res.ok).toBe(true);
      expect(res.data).toEqual(["mcp-a"]);
    });
  });

  describe("listBlocked", () => {
    it("returns empty block list", async () => {
      resetLastRequest();
      responseOverride = null;
      const client = makeClient();
      const res = await client.listBlocked();

      expect(res.ok).toBe(true);
      expect(res.data).toEqual([]);
    });
  });

  describe("listAlerts", () => {
    it("passes limit parameter", async () => {
      resetLastRequest();
      responseOverride = null;
      const client = makeClient();
      await client.listAlerts(10);

      expect(lastRequest.url).toBe("/alerts?limit=10");
    });

    it("uses default limit of 50", async () => {
      resetLastRequest();
      responseOverride = null;
      const client = makeClient();
      await client.listAlerts();

      expect(lastRequest.url).toBe("/alerts?limit=50");
    });
  });

  describe("logEvent", () => {
    it("posts event to /audit/event", async () => {
      resetLastRequest();
      responseOverride = null;
      const client = makeClient();
      const event = { action: "test", target: "/foo", severity: "INFO" };
      await client.logEvent(event);

      expect(lastRequest.method).toBe("POST");
      expect(lastRequest.url).toBe("/audit/event");
      expect(JSON.parse(lastRequest.body)).toEqual(event);
    });
  });

  describe("error handling", () => {
    it("returns ok=false on HTTP error status", async () => {
      resetLastRequest();
      responseOverride = { status: 500, body: "internal error" };
      const client = makeClient();
      const res = await client.status();

      expect(res.ok).toBe(false);
      expect(res.status).toBe(500);
      expect(res.error).toBe("internal error");
      responseOverride = null;
    });

    it("returns ok=false on HTTP 404", async () => {
      resetLastRequest();
      responseOverride = { status: 404, body: "not found" };
      const client = makeClient();
      const res = await client.listSkills();

      expect(res.ok).toBe(false);
      expect(res.status).toBe(404);
      responseOverride = null;
    });

    it("returns ok=false on connection refused", async () => {
      const client = new DaemonClient({
        baseUrl: "http://127.0.0.1:1",
        timeoutMs: 2000,
      });
      const res = await client.status();

      expect(res.ok).toBe(false);
      expect(res.status).toBe(0);
      expect(res.error).toBeDefined();
    });
  });

  describe("headers", () => {
    it("sets Content-Type and Accept headers", async () => {
      resetLastRequest();
      responseOverride = null;
      const client = makeClient();
      await client.status();

      expect(lastRequest.headers["content-type"]).toBe("application/json");
      expect(lastRequest.headers["accept"]).toBe("application/json");
    });

    it("sets Content-Length on POST requests", async () => {
      resetLastRequest();
      responseOverride = null;
      const client = makeClient();
      await client.logEvent({ foo: "bar" });

      expect(lastRequest.headers["content-length"]).toBeDefined();
    });
  });

  describe("evaluatePolicy", () => {
    it("sends domain and input, returns OPA result", async () => {
      resetLastRequest();
      responseOverride = null;
      const client = makeClient();
      const res = await client.evaluatePolicy("admission", {
        target_type: "skill",
        target_name: "test-skill",
      });

      expect(res.ok).toBe(true);
      expect(res.status).toBe(200);
      expect(lastRequest.method).toBe("POST");
      expect(lastRequest.url).toBe("/policy/evaluate");

      const sent = JSON.parse(lastRequest.body);
      expect(sent.domain).toBe("admission");
      expect(sent.input.target_type).toBe("skill");
    });

    it("handles server error gracefully", async () => {
      resetLastRequest();
      responseOverride = { status: 500, body: '{"error":"engine failed"}' };
      const client = makeClient();
      const res = await client.evaluatePolicy("admission", {});

      expect(res.ok).toBe(false);
      expect(res.status).toBe(500);
    });
  });
});
