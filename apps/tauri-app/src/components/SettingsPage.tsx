import { useState, useEffect } from 'react';
import { sidecarClient } from '@/services/sidecar-client';
import type { GuardrailConfig } from '@/types';

export function SettingsPage() {
  const [config, setConfig] = useState<GuardrailConfig | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  useEffect(() => {
    loadConfig();
  }, []);

  const loadConfig = async () => {
    setLoading(true);
    setError(null);
    try {
      const cfg = await sidecarClient.getGuardrailConfig();
      setConfig(cfg);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load configuration');
    } finally {
      setLoading(false);
    }
  };

  const handleSave = async () => {
    if (!config) return;

    setSaving(true);
    setError(null);
    setSuccess(null);
    try {
      await sidecarClient.updateGuardrailConfig(config);
      setSuccess('Settings saved successfully');
      setTimeout(() => setSuccess(null), 3000);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to save settings');
    } finally {
      setSaving(false);
    }
  };

  const updateConfig = (updates: Partial<GuardrailConfig>) => {
    if (!config) return;
    setConfig({ ...config, ...updates });
  };

  if (loading) {
    return (
      <div className="flex-1 flex items-center justify-center">
        <div className="text-gray-400">Loading settings...</div>
      </div>
    );
  }

  if (!config) {
    return (
      <div className="flex-1 flex items-center justify-center">
        <div className="text-red-400">Failed to load configuration</div>
      </div>
    );
  }

  return (
    <div className="flex-1 flex flex-col p-6 overflow-y-auto">
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-2xl font-bold text-cyan-400">Settings</h1>
        <button
          onClick={handleSave}
          disabled={saving}
          className="px-6 py-2 bg-cyan-600 hover:bg-cyan-700 disabled:bg-gray-700 disabled:text-gray-500 rounded-lg font-medium transition"
        >
          {saving ? 'Saving...' : 'Save Settings'}
        </button>
      </div>

      {error && (
        <div className="mb-4 p-3 bg-red-950/50 border border-red-600 rounded-lg text-red-400 text-sm">
          {error}
        </div>
      )}

      {success && (
        <div className="mb-4 p-3 bg-green-950/50 border border-green-600 rounded-lg text-green-400 text-sm">
          {success}
        </div>
      )}

      {/* Gateway Settings */}
      <div className="bg-gray-900 border border-gray-800 rounded-lg p-4 mb-4">
        <h2 className="text-lg font-semibold text-gray-100 mb-3">Gateway Connection</h2>
        <div className="space-y-3">
          <div>
            <label className="block text-sm text-gray-400 mb-1">Host</label>
            <input
              type="text"
              value="127.0.0.1"
              disabled
              className="w-full px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg text-gray-500 cursor-not-allowed"
            />
          </div>
          <div>
            <label className="block text-sm text-gray-400 mb-1">Port</label>
            <input
              type="text"
              value="18970"
              disabled
              className="w-full px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg text-gray-500 cursor-not-allowed"
            />
          </div>
          <p className="text-xs text-gray-500">Gateway connection settings are read-only</p>
        </div>
      </div>

      {/* Guardrail Settings */}
      <div className="bg-gray-900 border border-gray-800 rounded-lg p-4 mb-4">
        <h2 className="text-lg font-semibold text-gray-100 mb-3">Guardrails</h2>
        <div className="space-y-4">
          <label className="flex items-center justify-between p-3 bg-gray-950 rounded-lg cursor-pointer hover:bg-gray-900/50 transition">
            <div>
              <div className="font-medium text-gray-100">Enable Guardrails</div>
              <div className="text-xs text-gray-400">
                Enable security scanning and enforcement
              </div>
            </div>
            <input
              type="checkbox"
              checked={config.enabled}
              onChange={(e) => updateConfig({ enabled: e.target.checked })}
              className="w-5 h-5 text-cyan-600 bg-gray-800 border-gray-700 rounded focus:ring-cyan-600 focus:ring-2"
            />
          </label>

          <label className="flex items-center justify-between p-3 bg-gray-950 rounded-lg cursor-pointer hover:bg-gray-900/50 transition">
            <div>
              <div className="font-medium text-gray-100">Scan on Install</div>
              <div className="text-xs text-gray-400">
                Automatically scan skills and MCPs when installed
              </div>
            </div>
            <input
              type="checkbox"
              checked={config.scanOnInstall}
              onChange={(e) => updateConfig({ scanOnInstall: e.target.checked })}
              className="w-5 h-5 text-cyan-600 bg-gray-800 border-gray-700 rounded focus:ring-cyan-600 focus:ring-2"
            />
          </label>

          <label className="flex items-center justify-between p-3 bg-gray-950 rounded-lg cursor-pointer hover:bg-gray-900/50 transition">
            <div>
              <div className="font-medium text-gray-100">Block High Severity</div>
              <div className="text-xs text-gray-400">
                Automatically block HIGH and CRITICAL findings
              </div>
            </div>
            <input
              type="checkbox"
              checked={config.blockHighSeverity}
              onChange={(e) => updateConfig({ blockHighSeverity: e.target.checked })}
              className="w-5 h-5 text-cyan-600 bg-gray-800 border-gray-700 rounded focus:ring-cyan-600 focus:ring-2"
            />
          </label>

          <label className="flex items-center justify-between p-3 bg-gray-950 rounded-lg cursor-pointer hover:bg-gray-900/50 transition">
            <div>
              <div className="font-medium text-gray-100">Quarantine Suspicious</div>
              <div className="text-xs text-gray-400">
                Quarantine items with MEDIUM findings
              </div>
            </div>
            <input
              type="checkbox"
              checked={config.quarantineSuspicious}
              onChange={(e) => updateConfig({ quarantineSuspicious: e.target.checked })}
              className="w-5 h-5 text-cyan-600 bg-gray-800 border-gray-700 rounded focus:ring-cyan-600 focus:ring-2"
            />
          </label>
        </div>
      </div>

      {/* Scanner Settings */}
      <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
        <h2 className="text-lg font-semibold text-gray-100 mb-3">Scanners</h2>
        <div className="space-y-3">
          <div className="flex items-center justify-between p-3 bg-gray-950 rounded-lg">
            <div>
              <div className="font-medium text-gray-100">Skill Scanner</div>
              <div className="text-xs text-gray-400">Python-based skill analysis</div>
            </div>
            <span className="px-3 py-1 text-xs bg-green-950/50 border border-green-600 text-green-400 rounded">
              Active
            </span>
          </div>

          <div className="flex items-center justify-between p-3 bg-gray-950 rounded-lg">
            <div>
              <div className="font-medium text-gray-100">MCP Scanner</div>
              <div className="text-xs text-gray-400">MCP server security checks</div>
            </div>
            <span className="px-3 py-1 text-xs bg-green-950/50 border border-green-600 text-green-400 rounded">
              Active
            </span>
          </div>

          <div className="flex items-center justify-between p-3 bg-gray-950 rounded-lg">
            <div>
              <div className="font-medium text-gray-100">CodeGuard</div>
              <div className="text-xs text-gray-400">Static code analysis</div>
            </div>
            <span className="px-3 py-1 text-xs bg-green-950/50 border border-green-600 text-green-400 rounded">
              Active
            </span>
          </div>

          <div className="flex items-center justify-between p-3 bg-gray-950 rounded-lg">
            <div>
              <div className="font-medium text-gray-100">AIBOM</div>
              <div className="text-xs text-gray-400">AI Bill of Materials generation</div>
            </div>
            <span className="px-3 py-1 text-xs bg-green-950/50 border border-green-600 text-green-400 rounded">
              Active
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}
