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

  async scanSkill(skillId: string): Promise<ScanResult> {
    return this.request<ScanResult>(`/skills/${skillId}/scan`, {
      method: 'POST',
    });
  }

  async blockSkill(skillId: string): Promise<void> {
    await this.request(`/skills/${skillId}/block`, { method: 'POST' });
  }

  async allowSkill(skillId: string): Promise<void> {
    await this.request(`/skills/${skillId}/allow`, { method: 'POST' });
  }

  async quarantineSkill(skillId: string): Promise<void> {
    await this.request(`/skills/${skillId}/quarantine`, { method: 'POST' });
  }

  // MCP Server endpoints
  async getMCPServers(): Promise<MCPServer[]> {
    return this.request<MCPServer[]>('/mcp-servers');
  }

  async scanMCPServer(serverId: string): Promise<ScanResult> {
    return this.request<ScanResult>(`/mcp-servers/${serverId}/scan`, {
      method: 'POST',
    });
  }

  async blockMCPServer(serverId: string): Promise<void> {
    await this.request(`/mcp-servers/${serverId}/block`, { method: 'POST' });
  }

  async allowMCPServer(serverId: string): Promise<void> {
    await this.request(`/mcp-servers/${serverId}/allow`, { method: 'POST' });
  }

  async quarantineMCPServer(serverId: string): Promise<void> {
    await this.request(`/mcp-servers/${serverId}/quarantine`, {
      method: 'POST',
    });
  }

  // Guardrail configuration endpoints
  async getGuardrailConfig(): Promise<GuardrailConfig> {
    return this.request<GuardrailConfig>('/config/guardrails');
  }

  async updateGuardrailConfig(
    config: Partial<GuardrailConfig>
  ): Promise<GuardrailConfig> {
    return this.request<GuardrailConfig>('/config/guardrails', {
      method: 'PUT',
      body: JSON.stringify(config),
    });
  }

  // Scan result history
  async getScanHistory(params?: {
    limit?: number;
    targetType?: 'skill' | 'mcp-server' | 'tool';
  }): Promise<ScanResult[]> {
    const query = new URLSearchParams();
    if (params?.limit) query.set('limit', params.limit.toString());
    if (params?.targetType) query.set('targetType', params.targetType);

    const queryString = query.toString();
    return this.request<ScanResult[]>(
      `/scan-history${queryString ? `?${queryString}` : ''}`
    );
  }

  // Inventory endpoints
  async getInventory(): Promise<{
    skills: Skill[];
    mcpServers: MCPServer[];
    lastSync: string;
  }> {
    return this.request('/inventory');
  }

  async refreshInventory(): Promise<void> {
    await this.request('/inventory/refresh', { method: 'POST' });
  }
}

// Singleton instance
export const sidecarClient = new SidecarClient();
