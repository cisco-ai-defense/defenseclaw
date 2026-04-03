import { useState, useEffect } from 'react';
import { sidecarClient } from '@/services/sidecar-client';

export function PolicyPage() {
  const [policy, setPolicy] = useState<string>('# Loading policy...');
  const [loading, setLoading] = useState(false);
  const [reloading, setReloading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [blockedItems, setBlockedItems] = useState<Array<{ type: string; path: string }>>([]);
  const [allowedItems, setAllowedItems] = useState<Array<{ type: string; path: string }>>([]);

  useEffect(() => {
    loadPolicy();
  }, []);

  const loadPolicy = async () => {
    setLoading(true);
    setError(null);
    try {
      const [config, blocked, allowed] = await Promise.all([
        sidecarClient.getGuardrailConfig(),
        sidecarClient.getBlockedItems(),
        sidecarClient.getAllowedItems(),
      ]);

      setBlockedItems(blocked);
      setAllowedItems(allowed);

      // Format policy as YAML-like text
      const policyText = `# DefenseClaw Policy Configuration

enabled: ${config.enabled}
scanOnInstall: ${config.scanOnInstall}
blockHighSeverity: ${config.blockHighSeverity}
quarantineSuspicious: ${config.quarantineSuspicious}

# Block List (${config.blockList.length} items)
blockList:
${config.blockList.map((item) => `  - ${item}`).join('\n') || '  []'}

# Allow List (${config.allowList.length} items)
allowList:
${config.allowList.map((item) => `  - ${item}`).join('\n') || '  []'}
`;
      setPolicy(policyText);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load policy');
      setPolicy('# Failed to load policy');
    } finally {
      setLoading(false);
    }
  };

  const handleReload = async () => {
    setReloading(true);
    setError(null);
    setSuccess(null);
    try {
      await sidecarClient.reloadPolicy();
      await loadPolicy();
      setSuccess('Policy reloaded successfully');
      setTimeout(() => setSuccess(null), 3000);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to reload policy');
    } finally {
      setReloading(false);
    }
  };

  return (
    <div className="flex-1 flex flex-col p-6 overflow-y-auto">
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-2xl font-bold text-cyan-400">Policy Configuration</h1>
        <div className="flex gap-2">
          <button
            onClick={loadPolicy}
            disabled={loading}
            className="px-4 py-2 bg-gray-700 hover:bg-gray-600 disabled:bg-gray-800 disabled:text-gray-500 rounded-lg font-medium transition"
          >
            {loading ? 'Loading...' : 'Refresh'}
          </button>
          <button
            onClick={handleReload}
            disabled={reloading}
            className="px-4 py-2 bg-cyan-600 hover:bg-cyan-700 disabled:bg-gray-700 disabled:text-gray-500 rounded-lg font-medium transition"
          >
            {reloading ? 'Reloading...' : 'Reload Policy'}
          </button>
        </div>
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

      {/* Policy Viewer */}
      <div className="bg-gray-900 border border-gray-800 rounded-lg p-4 mb-6">
        <h2 className="text-lg font-semibold text-gray-100 mb-3">Policy YAML</h2>
        <pre className="bg-gray-950 p-4 rounded-lg overflow-x-auto text-sm text-gray-300 font-mono">
          {policy}
        </pre>
      </div>

      {/* Block List */}
      <div className="bg-gray-900 border border-gray-800 rounded-lg p-4 mb-4">
        <h2 className="text-lg font-semibold text-gray-100 mb-3">
          Blocked Items ({blockedItems.length})
        </h2>
        {blockedItems.length > 0 ? (
          <div className="space-y-2">
            {blockedItems.map((item, idx) => (
              <div
                key={idx}
                className="flex items-center justify-between p-2 bg-red-950/30 border border-red-800 rounded"
              >
                <div className="flex items-center gap-2">
                  <span className="text-xs px-2 py-1 bg-red-900 text-red-300 rounded font-mono">
                    {item.type}
                  </span>
                  <span className="text-sm text-gray-300 font-mono">{item.path}</span>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="text-sm text-gray-400">No blocked items</div>
        )}
      </div>

      {/* Allow List */}
      <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
        <h2 className="text-lg font-semibold text-gray-100 mb-3">
          Allowed Items ({allowedItems.length})
        </h2>
        {allowedItems.length > 0 ? (
          <div className="space-y-2">
            {allowedItems.map((item, idx) => (
              <div
                key={idx}
                className="flex items-center justify-between p-2 bg-green-950/30 border border-green-800 rounded"
              >
                <div className="flex items-center gap-2">
                  <span className="text-xs px-2 py-1 bg-green-900 text-green-300 rounded font-mono">
                    {item.type}
                  </span>
                  <span className="text-sm text-gray-300 font-mono">{item.path}</span>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="text-sm text-gray-400">No allowed items</div>
        )}
      </div>
    </div>
  );
}
