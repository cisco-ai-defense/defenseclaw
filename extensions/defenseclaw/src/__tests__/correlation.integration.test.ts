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

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createServer } from "node:http";
import type { Server, IncomingMessage, ServerResponse } from "node:http";
import {
  HEADER_DEFENSECLAW_AGENT_ID,
  HEADER_DEFENSECLAW_AGENT_INSTANCE_ID,
  HEADER_DEFENSECLAW_RUN_ID,
  HEADER_DEFENSECLAW_SESSION_ID,
  HEADER_DEFENSECLAW_TRACE_ID,
} from "../correlation-headers.js";
import { DaemonClient } from "../client.js";

let server: Server;
let port: number;
let lastHeaders: Record<string, string | string[] | undefined> = {};

beforeAll(
  () =>
    new Promise<void>((resolve) => {
      server = createServer((req: IncomingMessage, res: ServerResponse) => {
        lastHeaders = req.headers;
        res.writeHead(200, {
          "Content-Type": "application/json",
          "X-DefenseClaw-Agent-Instance-Id": "integration-echo-inst",
          "X-DefenseClaw-Sidecar-Instance-Id": "integration-sidecar",
        });
        res.end(JSON.stringify({ ok: true }));
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

describe("sidecar correlation integration", () => {
  it("round-trips correlation context over HTTP and applies sticky instance id", async () => {
    const client = new DaemonClient({
      baseUrl: `http://127.0.0.1:${port}`,
      token: "",
      getCorrelation: () => ({
        agentId: "logical-agent",
        agentInstanceId: "minted-local",
        runId: "run-1",
        sessionId: "sess-1",
        traceId: "trace-1",
      }),
    });

    await client.status();

    expect(lastHeaders[HEADER_DEFENSECLAW_AGENT_ID.toLowerCase()]).toBe(
      "logical-agent",
    );
    expect(
      lastHeaders[HEADER_DEFENSECLAW_AGENT_INSTANCE_ID.toLowerCase()],
    ).toBe("minted-local");
    expect(lastHeaders[HEADER_DEFENSECLAW_RUN_ID.toLowerCase()]).toBe("run-1");
    expect(lastHeaders[HEADER_DEFENSECLAW_SESSION_ID.toLowerCase()]).toBe(
      "sess-1",
    );
    expect(lastHeaders[HEADER_DEFENSECLAW_TRACE_ID.toLowerCase()]).toBe(
      "trace-1",
    );

    await client.status();
    expect(
      lastHeaders[HEADER_DEFENSECLAW_AGENT_INSTANCE_ID.toLowerCase()],
    ).toBe("integration-echo-inst");
    expect(client.getStickyAgentInstanceId()).toBe("integration-echo-inst");
    expect(client.getEchoedSidecarInstanceId()).toBe("integration-sidecar");
  });
});
