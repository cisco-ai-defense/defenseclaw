#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { executeApprovedRequest, executeReusablePermit } from "./executor.js";
import { buildEnvCommandAction, buildSshSessionAction, scanLocalFile, scanLocalText } from "./gateway.js";
import { SecretStore } from "./store.js";
import { defaultSshInjectEnv } from "./ssh.js";
import { CURRENT_VERSION } from "./version.js";

const store = new SecretStore();
const server = new McpServer({
  name: "s-gw",
  version: CURRENT_VERSION
});

function mcpAgentContext() {
  return { mcpClientName: server.server.getClientVersion()?.name };
}

server.registerTool(
  "sgw_scan_file",
  {
    title: "Scan Local File",
    description: "Scan a local file for secrets and return tokenized text plus local handles. Raw values are not returned.",
    inputSchema: {
      path: z.string().min(1),
      persist: z.boolean().optional()
    }
  },
  async ({ path, persist }) => asText(await scanLocalFile(store, path, { persist: persist ?? true }))
);

server.registerTool(
  "sgw_scan_text",
  {
    title: "Scan Text",
    description: "Scan supplied text and return tokenized text. Persist=false previews handles without enrolling secrets.",
    inputSchema: {
      text: z.string(),
      persist: z.boolean().optional(),
      source: z.string().optional()
    }
  },
  async ({ text, persist, source }) => asText(await scanLocalText(store, text, { persist: persist === true, source }))
);

server.registerTool(
  "sgw_list_handles",
  {
    title: "List Handles",
    description: "List known local secret handles and non-secret metadata.",
    inputSchema: {}
  },
  async () => asText(await store.listHandles())
);

server.registerTool(
  "sgw_describe_handle",
  {
    title: "Describe Handle",
    description: "Show non-secret metadata for one local secret handle.",
    inputSchema: {
      handle: z.string().min(1)
    }
  },
  async ({ handle }) => asText(await store.getHandle(handle) ?? { error: "unknown_handle", handle })
);

server.registerTool(
  "sgw_request_execution",
  {
    title: "Request Secret-Backed Execution",
    description: "Create a pending local manifest for a command that needs one secret injected as an environment variable.",
    inputSchema: {
      handle: z.string().min(1),
      command: z.string().min(1),
      args: z.array(z.string()).optional(),
      injectEnv: z.string().min(1),
      env: z.array(z.object({
        handle: z.string().min(1),
        injectEnv: z.string().min(1)
      })).optional(),
      workingDir: z.string().optional(),
      timeoutMs: z.number().int().nonnegative().optional(),
      reason: z.string().optional()
    }
  },
  async ({ handle, command, args, injectEnv, env, workingDir, timeoutMs, reason }) => {
    const action = buildEnvCommandAction({ command, args, injectEnv, env, workingDir, timeoutMs });
    const request = await store.createRequest(
      handle,
      action,
      reason || "Agent requested local secret-backed execution.",
      mcpAgentContext()
    );
    return asText({
      approvalRequired: request.state !== "approved",
      localApprovalCommand: request.state === "approved" ? undefined : `s-gw approve ${request.id}`,
      request
    });
  }
);

server.registerTool(
  "sgw_run_execution",
  {
    title: "Run Secret-Backed Execution",
    description: "Run a command through reusable local approval without creating a ledger record for every invocation.",
    inputSchema: {
      handle: z.string().min(1),
      command: z.string().min(1),
      args: z.array(z.string()).optional(),
      injectEnv: z.string().min(1),
      env: z.array(z.object({
        handle: z.string().min(1),
        injectEnv: z.string().min(1)
      })).optional(),
      workingDir: z.string().optional(),
      timeoutMs: z.number().int().nonnegative().optional(),
      reason: z.string().optional()
    }
  },
  async ({ handle, command, args, injectEnv, env, workingDir, timeoutMs, reason }) => {
    const action = buildEnvCommandAction({ command, args, injectEnv, env, workingDir, timeoutMs });
    const admission = await store.prepareOneShotExecution(
      handle,
      action,
      reason || "Agent requested reusable local secret-backed execution.",
      mcpAgentContext()
    );
    if (admission.kind === "request") {
      return asText({
        approvalRequired: admission.request.state !== "approved",
        localApprovalCommand: admission.request.state === "approved" ? undefined : `s-gw approve ${admission.request.id}`,
        request: admission.request
      });
    }
    return asText({
      approvalRequired: false,
      reusableAuthorization: admission.permit.authorization,
      summary: await executeReusablePermit(store, admission.permit)
    });
  }
);

server.registerTool(
  "sgw_request_ssh_session",
  {
    title: "Request s-gw-Owned SSH Session",
    description: "Create a local approval request for an SSH command. Unix-like systems use an s-gw-owned ControlMaster; Windows uses a hardened one-shot ssh.exe command with an SSH private key.",
    inputSchema: {
      handle: z.string().min(1),
      target: z.string().min(1),
      port: z.number().int().positive().optional(),
      args: z.array(z.string()).optional(),
      injectEnv: z.string().optional(),
      workingDir: z.string().optional(),
      timeoutMs: z.number().int().nonnegative().optional(),
      reason: z.string().optional()
    }
  },
  async ({ handle, target, port, args, injectEnv, workingDir, timeoutMs, reason }) => {
    const secret = await store.getSecretRecord(handle);
    const action = buildSshSessionAction({
      target,
      port,
      args,
      injectEnv: injectEnv || defaultSshInjectEnv(secret),
      workingDir,
      timeoutMs
    });
    const request = await store.createRequest(
      handle,
      action,
      reason || "Agent requested s-gw-owned SSH access.",
      mcpAgentContext()
    );
    return asText({
      approvalRequired: request.state !== "approved",
      localApprovalCommand: request.state === "approved" ? undefined : `s-gw approve ${request.id}`,
      request
    });
  }
);

server.registerTool(
  "sgw_execute_request",
  {
    title: "Execute Approved Request",
    description: "Execute a previously approved local request and return sanitized output.",
    inputSchema: {
      requestId: z.string().min(1)
    }
  },
  async ({ requestId }) => asText(await executeApprovedRequest(store, requestId))
);

function asText(value: unknown) {
  return {
    content: [
      {
        type: "text" as const,
        text: JSON.stringify(value, null, 2)
      }
    ]
  };
}

await server.connect(new StdioServerTransport());
