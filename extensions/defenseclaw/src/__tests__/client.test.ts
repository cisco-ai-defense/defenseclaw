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
import type { IncomingHttpHeaders } from "node:http";
import { PassThrough } from "node:stream";
import { beforeEach, describe, expect, it } from "vitest";
import {
  HEADER_DEFENSECLAW_AGENT_ID,
  HEADER_DEFENSECLAW_AGENT_INSTANCE_ID,
} from "../correlation-headers.js";
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
  responseHeaders?: IncomingHttpHeaders;
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

        const res = new PassThrough() as PassThrough & {
          statusCode?: number;
          headers: IncomingHttpHeaders;
        };
        res.statusCode = response.status;
        res.headers = response.responseHeaders ?? {};
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
  extra?: {
    getCorrelation?: () => import("../types.js").CorrelationContext;
    logOutboundRequest?: (e: import("../types.js").OutboundSidecarRequestLog) => void;
  },
): DaemonClient {
  return new DaemonClient({
    baseUrl: "http://127.0.0.1:18970",
    requestImpl: createRequestImpl(resolver),
    getCorrelation:
      extra?.getCorrelation ??
      (() => ({
        agentId: "test-agent",
        agentInstanceId: "session-instance-1",
        traceId: "trace-fixed",
      })),
    logOutboundRequest: extra?.logOutboundRequest,
  });
}

beforeEach(() => {
  resetLastRequest();
  responseOverride = null;
});

describe("DaemonClient", () => {
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

  describe("listBlocked", () => {
    it("returns empty block list", async () => {
      const client = makeClient();
      const res = await client.listBlocked();

      expect(res.ok).toBe(true);
      expect(res.data).toEqual([]);
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
      const res = await client.listBlocked();

      expect(res.ok).toBe(false);
      expect(res.status).toBe(500);
      expect(res.error).toBe("internal error");
    });

    it("returns ok=false on HTTP 404", async () => {
      responseOverride = { status: 404, body: "not found" };
      const client = makeClient();
      const res = await client.listBlocked();

      expect(res.ok).toBe(false);
      expect(res.status).toBe(404);
    });

    it("returns ok=false on request errors", async () => {
      const client = makeClient(() => ({
        status: 0,
        requestError: new Error("connect ECONNREFUSED 127.0.0.1:18970"),
      }));
      const res = await client.listBlocked();

      expect(res.ok).toBe(false);
      expect(res.status).toBe(0);
      expect(res.error).toContain("ECONNREFUSED");
    });
  });

  describe("headers", () => {
    it("sets Content-Type and Accept headers", async () => {
      const client = makeClient();
      await client.listBlocked();

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
      await client.listBlocked();

      expect(lastRequest.headers["X-DefenseClaw-Client"]).toBe(
        "openclaw-plugin",
      );
    });

    it("names the client and the openclaw connector on POST requests", async () => {
      const client = makeClient();
      await client.logEvent({ foo: "bar" });

      expect(lastRequest.headers["X-DefenseClaw-Client"]).toBe(
        "openclaw-plugin",
      );
      expect(lastRequest.headers["x-defenseclaw-connector"] ?? lastRequest.headers["X-DefenseClaw-Connector"]).toBe(
        "openclaw",
      );
    });

    it("has no call that loosens policy", () => {
      const client = makeClient() as unknown as Record<string, unknown>;
      for (const name of ["block", "allow", "unblock", "status", "listAlerts"]) {
        expect(client[name]).toBeUndefined();
      }
    });

    it("includes X-DefenseClaw-Agent-Id and instance id from correlation", async () => {
      const client = makeClient();
      await client.listBlocked();

      expect(lastRequest.headers[HEADER_DEFENSECLAW_AGENT_ID]).toBe("test-agent");
      expect(lastRequest.headers[HEADER_DEFENSECLAW_AGENT_INSTANCE_ID]).toBe(
        "session-instance-1",
      );
    });

    it("uses sticky agent instance id from first response on subsequent requests", async () => {
      let call = 0;
      const client = makeClient(() => {
        call += 1;
        if (call === 1) {
          return {
            status: 200,
            body: JSON.stringify({ running: true }),
            responseHeaders: {
              "x-defenseclaw-agent-instance-id": "sidecar-echo-99",
            },
          };
        }
        return {
          status: 200,
          body: JSON.stringify({ running: true }),
        };
      });

      await client.listBlocked();
      expect(lastRequest.headers[HEADER_DEFENSECLAW_AGENT_INSTANCE_ID]).toBe(
        "session-instance-1",
      );

      await client.listBlocked();
      expect(lastRequest.headers[HEADER_DEFENSECLAW_AGENT_INSTANCE_ID]).toBe(
        "sidecar-echo-99",
      );
    });

    it("emits structured outbound log when logOutboundRequest is set", async () => {
      const logs: import("../types.js").OutboundSidecarRequestLog[] = [];
      const client = makeClient(undefined, {
        logOutboundRequest: (e) => logs.push(e),
      });
      await client.listBlocked();

      expect(logs).toHaveLength(1);
      expect(logs[0].agentId).toBe("test-agent");
      expect(logs[0].status_code).toBe(200);
      expect(typeof logs[0].duration_ms).toBe("number");
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
