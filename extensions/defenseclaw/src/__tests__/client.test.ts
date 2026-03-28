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

import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import { beforeEach, describe, expect, it } from "vitest";
import { DaemonClient } from "../client.js";

type HeaderValue = string | number | string[] | undefined;

type RecordedRequest = {
  method: string;
  url: string;
  body: string;
  headers: Record<string, HeaderValue>;
};

type MockResponse = {
  status: number;
  body?: string;
  requestError?: Error;
};

let lastRequest: RecordedRequest;
let responseOverride: MockResponse | null = null;

function resetLastRequest() {
  lastRequest = { method: "", url: "", body: "", headers: {} };
}

function defaultResponse(request: RecordedRequest): MockResponse {
  if (request.url === "/status") {
    return {
      status: 200,
      body: JSON.stringify({ running: true, uptime_seconds: 42 }),
    };
  }
  if (request.url === "/enforce/blocked" || request.url === "/enforce/allowed") {
    return { status: 200, body: JSON.stringify([]) };
  }
  if (request.url === "/skills") {
    return { status: 200, body: JSON.stringify(["skill-a", "skill-b"]) };
  }
  if (request.url === "/mcps") {
    return { status: 200, body: JSON.stringify(["mcp-a"]) };
  }
  if (request.url.startsWith("/alerts")) {
    return { status: 200, body: JSON.stringify([]) };
  }
  if (request.url === "/policy/evaluate" && request.method === "POST") {
    const payload = JSON.parse(request.body || "{}") as {
      domain?: string;
    };
    return {
      status: 200,
      body: JSON.stringify({
        ok: true,
        data: {
          verdict: "clean",
          reason: "test policy result",
          domain: payload.domain,
        },
      }),
    };
  }
  return { status: 200, body: "{}" };
}

function createRequestImpl(
  resolver: (request: RecordedRequest) => MockResponse = (request) =>
    responseOverride ?? defaultResponse(request),
) {
  return ((options: {
    method?: string;
    path?: string;
    headers?: Record<string, HeaderValue>;
  }, callback: (res: PassThrough & { statusCode?: number }) => void) => {
    const req = new EventEmitter() as EventEmitter & {
      write: (chunk: string | Buffer) => boolean;
      end: () => void;
      destroy: () => void;
    };

    let body = "";

    req.write = (chunk) => {
      body += Buffer.isBuffer(chunk) ? chunk.toString("utf-8") : chunk;
      return true;
    };

    req.destroy = () => undefined;

    req.end = () => {
      lastRequest = {
        method: options.method ?? "GET",
        url: options.path ?? "/",
        body,
        headers: options.headers ?? {},
      };

      const response = resolver(lastRequest);
      queueMicrotask(() => {
        if (response.requestError) {
          req.emit("error", response.requestError);
          return;
        }

        const res = new PassThrough() as PassThrough & { statusCode?: number };
        res.statusCode = response.status;
        callback(res);
        if (response.body) {
          res.write(response.body);
        }
        res.end();
      });
    };

    return req;
  }) as unknown as typeof import("node:http").request;
}

function makeClient(
  resolver?: (request: RecordedRequest) => MockResponse,
): DaemonClient {
  return new DaemonClient({
    baseUrl: "http://127.0.0.1:18970",
    requestImpl: createRequestImpl(resolver),
  });
}

beforeEach(() => {
  resetLastRequest();
  responseOverride = null;
});

describe("DaemonClient", () => {
  describe("status", () => {
    it("returns daemon status on success", async () => {
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
      const client = makeClient();
      const res = await client.listSkills();

      expect(res.ok).toBe(true);
      expect(res.data).toEqual(["skill-a", "skill-b"]);
    });
  });

  describe("listMCPs", () => {
    it("returns MCP list", async () => {
      const client = makeClient();
      const res = await client.listMCPs();

      expect(res.ok).toBe(true);
      expect(res.data).toEqual(["mcp-a"]);
    });
  });

  describe("listBlocked", () => {
    it("returns empty block list", async () => {
      const client = makeClient();
      const res = await client.listBlocked();

      expect(res.ok).toBe(true);
      expect(res.data).toEqual([]);
    });
  });

  describe("listAlerts", () => {
    it("passes limit parameter", async () => {
      const client = makeClient();
      await client.listAlerts(10);

      expect(lastRequest.url).toBe("/alerts?limit=10");
    });

    it("uses default limit of 50", async () => {
      const client = makeClient();
      await client.listAlerts();

      expect(lastRequest.url).toBe("/alerts?limit=50");
    });
  });

  describe("logEvent", () => {
    it("posts event to /audit/event", async () => {
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
      responseOverride = { status: 500, body: "internal error" };
      const client = makeClient();
      const res = await client.status();

      expect(res.ok).toBe(false);
      expect(res.status).toBe(500);
      expect(res.error).toBe("internal error");
    });

    it("returns ok=false on HTTP 404", async () => {
      responseOverride = { status: 404, body: "not found" };
      const client = makeClient();
      const res = await client.listSkills();

      expect(res.ok).toBe(false);
      expect(res.status).toBe(404);
    });

    it("returns ok=false on request errors", async () => {
      const client = makeClient(() => ({
        status: 0,
        requestError: new Error("connect ECONNREFUSED 127.0.0.1:18970"),
      }));
      const res = await client.status();

      expect(res.ok).toBe(false);
      expect(res.status).toBe(0);
      expect(res.error).toContain("ECONNREFUSED");
    });
  });

  describe("headers", () => {
    it("sets Content-Type and Accept headers", async () => {
      const client = makeClient();
      await client.status();

      expect(lastRequest.headers["Content-Type"]).toBe("application/json");
      expect(lastRequest.headers.Accept).toBe("application/json");
    });

    it("sets Content-Length on POST requests", async () => {
      const client = makeClient();
      await client.logEvent({ foo: "bar" });

      expect(lastRequest.headers["Content-Length"]).toBeDefined();
    });

    it("includes X-DefenseClaw-Client header on GET requests", async () => {
      const client = makeClient();
      await client.status();

      expect(lastRequest.headers["X-DefenseClaw-Client"]).toBe(
        "openclaw-plugin",
      );
    });

    it("includes X-DefenseClaw-Client header on POST requests", async () => {
      const client = makeClient();
      await client.block("skill", "evil-skill", "malware");

      expect(lastRequest.headers["X-DefenseClaw-Client"]).toBe(
        "openclaw-plugin",
      );
    });

    it("includes X-DefenseClaw-Client header on DELETE requests", async () => {
      const client = makeClient();
      await client.unblock("skill", "temp-skill");

      expect(lastRequest.headers["X-DefenseClaw-Client"]).toBe(
        "openclaw-plugin",
      );
    });
  });

  describe("evaluatePolicy", () => {
    it("sends domain and input, returns OPA result", async () => {
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
      responseOverride = { status: 500, body: '{"error":"engine failed"}' };
      const client = makeClient();
      const res = await client.evaluatePolicy("admission", {});

      expect(res.ok).toBe(false);
      expect(res.status).toBe(500);
    });
  });
});
