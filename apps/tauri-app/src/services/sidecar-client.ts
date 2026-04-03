import type {
  HealthSnapshot,
  Alert,
  Skill,
  MCPServer,
  ScanResult,
  GuardrailConfig,
} from '@/types';

const SIDECAR_BASE_URL = 'http://127.0.0.1:18970';

export class SidecarClient {
  private baseUrl: string;

  constructor(baseUrl: string = SIDECAR_BASE_URL) {
    this.baseUrl = baseUrl;
  }

  private async request<T>(
    endpoint: string,
    options?: RequestInit
  ): Promise<T> {
    const response = await fetch(`${this.baseUrl}${endpoint}`, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        ...options?.headers,
      },
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(
        `Sidecar request failed: ${response.status} ${errorText}`
      );
    }

    return response.json();
  }

  // Health endpoints
  async getHealth(): Promise<HealthSnapshot> {
    return this.request<HealthSnapshot>('/health');
  }

  // Alert endpoints
  async getAlerts(params?: {
    limit?: number;
    severity?: string;
    source?: string;
  }): Promise<Alert[]> {
    const query = new URLSearchParams();
    if (params?.limit) query.set('limit', params.limit.toString());
    if (params?.severity) query.set('severity', params.severity);
    if (params?.source) query.set('source', params.source);

    const queryString = query.toString();
    return this.request<Alert[]>(`/alerts${queryString ? `?${queryString}` : ''}`);
  }

  async markAlertRead(alertId: string): Promise<void> {
    await this.request(`/alerts/${alertId}/read`, { method: 'POST' });
  }

  // Skill endpoints
  async getSkills(): Promise<Skill[]> {
    return this.request<Skill[]>('/skills');
  }

  async scanSkill(path: string): Promise<ScanResult> {
    return this.request<ScanResult>('/v1/skill/scan', {
      method: 'POST',
      body: JSON.stringify({ path }),
    });
  }

  async blockSkill(path: string): Promise<void> {
    await this.request('/enforce/block', {
      method: 'POST',
      body: JSON.stringify({ type: 'skill', path }),
    });
  }

  async allowSkill(path: string): Promise<void> {
    await this.request('/enforce/allow', {
      method: 'POST',
      body: JSON.stringify({ type: 'skill', path }),
    });
  }

  // MCP Server endpoints
  async getMCPServers(): Promise<MCPServer[]> {
    return this.request<MCPServer[]>('/mcps');
  }

  async scanMCPServer(path: string): Promise<ScanResult> {
    return this.request<ScanResult>('/v1/mcp/scan', {
      method: 'POST',
      body: JSON.stringify({ path }),
    });
  }

  async blockMCPServer(path: string): Promise<void> {
    await this.request('/enforce/block', {
      method: 'POST',
      body: JSON.stringify({ type: 'mcp', path }),
    });
  }

  async allowMCPServer(path: string): Promise<void> {
    await this.request('/enforce/allow', {
      method: 'POST',
      body: JSON.stringify({ type: 'mcp', path }),
    });
  }

  // Guardrail configuration endpoints
  async getGuardrailConfig(): Promise<GuardrailConfig> {
    return this.request<GuardrailConfig>('/v1/guardrail/config');
  }

  async updateGuardrailConfig(
    config: Partial<GuardrailConfig>
  ): Promise<GuardrailConfig> {
    return this.request<GuardrailConfig>('/v1/guardrail/config', {
      method: 'PUT',
      body: JSON.stringify(config),
    });
  }

  // Block/Allow list endpoints
  async getBlockedItems(): Promise<Array<{ type: string; path: string }>> {
    return this.request('/enforce/blocked');
  }

  async getAllowedItems(): Promise<Array<{ type: string; path: string }>> {
    return this.request('/enforce/allowed');
  }

  // Policy reload
  async reloadPolicy(): Promise<void> {
    await this.request('/policy/reload', { method: 'POST' });
  }
}

// Singleton instance
export const sidecarClient = new SidecarClient();
