import { request as httpRequest } from "node:http";
import { URL } from "node:url";
import type {
  ScanResult,
  BlockEntry,
  AllowEntry,
  DaemonStatus,
  AdmissionResult,
} from "./types.js";

const DEFAULT_BASE_URL = "http://127.0.0.1:18789";
const REQUEST_TIMEOUT_MS = 30_000;
const MAX_RESPONSE_BYTES = 10 * 1024 * 1024;

interface ClientOptions {
  baseUrl?: string;
  timeoutMs?: number;
}

interface ApiResponse<T> {
  ok: boolean;
  data?: T;
  error?: string;
  status: number;
}

export class DaemonClient {
  private readonly baseUrl: string;
  private readonly timeoutMs: number;

  constructor(opts?: ClientOptions) {
    this.baseUrl = opts?.baseUrl ?? DEFAULT_BASE_URL;
    this.timeoutMs = opts?.timeoutMs ?? REQUEST_TIMEOUT_MS;
  }

  async status(): Promise<ApiResponse<DaemonStatus>> {
    return this.get<DaemonStatus>("/status");
  }

  async submitScanResult(result: ScanResult): Promise<ApiResponse<void>> {
    return this.post<void>("/scan/result", result);
  }

  async block(
    targetType: string,
    targetName: string,
    reason: string,
  ): Promise<ApiResponse<void>> {
    return this.post<void>("/enforce/block", {
      target_type: targetType,
      target_name: targetName,
      reason,
    });
  }

  async allow(
    targetType: string,
    targetName: string,
    reason: string,
  ): Promise<ApiResponse<void>> {
    return this.post<void>("/enforce/allow", {
      target_type: targetType,
      target_name: targetName,
      reason,
    });
  }

  async unblock(
    targetType: string,
    targetName: string,
  ): Promise<ApiResponse<void>> {
    return this.delete<void>("/enforce/block", {
      target_type: targetType,
      target_name: targetName,
    });
  }

  async listAlerts(limit = 50): Promise<ApiResponse<AdmissionResult[]>> {
    return this.get<AdmissionResult[]>(`/alerts?limit=${limit}`);
  }

  async listSkills(): Promise<ApiResponse<string[]>> {
    return this.get<string[]>("/skills");
  }

  async listMCPs(): Promise<ApiResponse<string[]>> {
    return this.get<string[]>("/mcps");
  }

  async listBlocked(): Promise<ApiResponse<BlockEntry[]>> {
    return this.get<BlockEntry[]>("/enforce/blocked");
  }

  async listAllowed(): Promise<ApiResponse<AllowEntry[]>> {
    return this.get<AllowEntry[]>("/enforce/allowed");
  }

  async logEvent(event: Record<string, unknown>): Promise<ApiResponse<void>> {
    return this.post<void>("/audit/event", event);
  }

  async evaluatePolicy(
    domain: string,
    input: Record<string, unknown>,
  ): Promise<ApiResponse<Record<string, unknown>>> {
    return this.post<Record<string, unknown>>("/policy/evaluate", {
      domain,
      input,
    });
  }

  private get<T>(path: string): Promise<ApiResponse<T>> {
    return this.doRequest<T>("GET", path);
  }

  private post<T>(path: string, body: unknown): Promise<ApiResponse<T>> {
    return this.doRequest<T>("POST", path, body);
  }

  private delete<T>(path: string, body: unknown): Promise<ApiResponse<T>> {
    return this.doRequest<T>("DELETE", path, body);
  }

  private doRequest<T>(
    method: string,
    path: string,
    body?: unknown,
  ): Promise<ApiResponse<T>> {
    return new Promise((resolve) => {
      const url = new URL(path, this.baseUrl);
      const payload = body !== undefined ? JSON.stringify(body) : undefined;

      const req = httpRequest(
        {
          hostname: url.hostname,
          port: url.port,
          path: url.pathname + url.search,
          method,
          timeout: this.timeoutMs,
          headers: {
            "Content-Type": "application/json",
            Accept: "application/json",
            ...(payload !== undefined
              ? { "Content-Length": Buffer.byteLength(payload) }
              : {}),
          },
        },
        (res) => {
          const chunks: Buffer[] = [];
          let totalBytes = 0;

          res.on("data", (chunk: Buffer) => {
            totalBytes += chunk.length;
            if (totalBytes <= MAX_RESPONSE_BYTES) {
              chunks.push(chunk);
            }
          });

          res.on("end", () => {
            const raw = Buffer.concat(chunks).toString("utf-8");
            const status = res.statusCode ?? 0;

            if (status >= 200 && status < 300) {
              try {
                const data = raw.length > 0 ? (JSON.parse(raw) as T) : undefined;
                resolve({ ok: true, data, status });
              } catch {
                resolve({ ok: true, data: undefined, status });
              }
            } else {
              resolve({ ok: false, error: raw || `HTTP ${status}`, status });
            }
          });

          res.on("error", (err) => {
            resolve({ ok: false, error: err.message, status: 0 });
          });
        },
      );

      req.on("error", (err) => {
        resolve({ ok: false, error: err.message, status: 0 });
      });

      req.on("timeout", () => {
        req.destroy();
        resolve({ ok: false, error: "request timed out", status: 0 });
      });

      if (payload !== undefined) {
        req.write(payload);
      }
      req.end();
    });
  }
}
