import { useState } from 'react';
import { sidecarClient } from '@/services/sidecar-client';
import type { ScanResult, Finding } from '@/types';

type ScanType = 'skill' | 'mcp' | 'aibom';

export function ScanPage() {
  const [scanType, setScanType] = useState<ScanType>('skill');
  const [path, setPath] = useState('');
  const [scanning, setScanning] = useState(false);
  const [results, setResults] = useState<ScanResult[]>([]);
  const [error, setError] = useState<string | null>(null);

  const handleScan = async () => {
    if (!path.trim()) {
      setError('Please enter a path to scan');
      return;
    }

    setScanning(true);
    setError(null);

    try {
      let result: ScanResult;
      if (scanType === 'skill') {
        result = await sidecarClient.scanSkill(path);
      } else if (scanType === 'mcp') {
        result = await sidecarClient.scanMCPServer(path);
      } else {
        throw new Error('AIBOM scan not yet implemented');
      }
      setResults([result, ...results]);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Scan failed');
    } finally {
      setScanning(false);
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'CRITICAL':
        return 'text-red-500 bg-red-950/50 border-red-600';
      case 'HIGH':
        return 'text-orange-500 bg-orange-950/50 border-orange-600';
      case 'MEDIUM':
        return 'text-yellow-500 bg-yellow-950/50 border-yellow-600';
      case 'LOW':
        return 'text-blue-500 bg-blue-950/50 border-blue-600';
      case 'INFO':
        return 'text-gray-400 bg-gray-950/50 border-gray-600';
      default:
        return 'text-gray-400 bg-gray-950/50 border-gray-600';
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'clean':
        return 'text-green-400';
      case 'suspicious':
        return 'text-yellow-400';
      case 'malicious':
        return 'text-red-400';
      default:
        return 'text-gray-400';
    }
  };

  const renderFinding = (finding: Finding, idx: number) => (
    <div key={idx} className={`p-3 rounded-lg border ${getSeverityColor(finding.severity)} mb-2`}>
      <div className="flex items-start justify-between mb-1">
        <span className="font-semibold text-sm">{finding.category}</span>
        <span className="text-xs px-2 py-1 rounded bg-gray-900">{finding.severity}</span>
      </div>
      <p className="text-sm text-gray-300 mb-2">{finding.message}</p>
      {finding.location && (
        <div className="text-xs text-gray-400 mb-1">Location: {finding.location}</div>
      )}
      {finding.evidence && (
        <pre className="text-xs bg-gray-950 p-2 rounded overflow-x-auto text-gray-300 mb-1">
          {finding.evidence}
        </pre>
      )}
      {finding.recommendation && (
        <div className="text-xs text-cyan-400 mt-2">💡 {finding.recommendation}</div>
      )}
    </div>
  );

  return (
    <div className="flex-1 flex flex-col p-6 overflow-y-auto">
      <h1 className="text-2xl font-bold text-cyan-400 mb-6">Security Scan</h1>

      {/* Scan Controls */}
      <div className="bg-gray-900 border border-gray-800 rounded-lg p-4 mb-6">
        <div className="flex gap-4 mb-4">
          <button
            onClick={() => setScanType('skill')}
            className={`px-4 py-2 rounded-lg font-medium transition ${
              scanType === 'skill'
                ? 'bg-cyan-600 text-white'
                : 'bg-gray-800 text-gray-400 hover:bg-gray-700'
            }`}
          >
            Skill Scan
          </button>
          <button
            onClick={() => setScanType('mcp')}
            className={`px-4 py-2 rounded-lg font-medium transition ${
              scanType === 'mcp'
                ? 'bg-cyan-600 text-white'
                : 'bg-gray-800 text-gray-400 hover:bg-gray-700'
            }`}
          >
            MCP Scan
          </button>
          <button
            onClick={() => setScanType('aibom')}
            className={`px-4 py-2 rounded-lg font-medium transition ${
              scanType === 'aibom'
                ? 'bg-cyan-600 text-white'
                : 'bg-gray-800 text-gray-400 hover:bg-gray-700'
            }`}
          >
            AIBOM
          </button>
        </div>

        <div className="flex gap-2">
          <input
            type="text"
            value={path}
            onChange={(e) => setPath(e.target.value)}
            placeholder={`Enter path to ${scanType}...`}
            className="flex-1 px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg focus:outline-none focus:ring-2 focus:ring-cyan-600 text-gray-100"
            onKeyDown={(e) => e.key === 'Enter' && handleScan()}
          />
          <button
            onClick={handleScan}
            disabled={scanning || !path.trim()}
            className="px-6 py-2 bg-cyan-600 hover:bg-cyan-700 disabled:bg-gray-700 disabled:text-gray-500 rounded-lg font-medium transition"
          >
            {scanning ? 'Scanning...' : 'Scan'}
          </button>
        </div>

        {error && (
          <div className="mt-4 p-3 bg-red-950/50 border border-red-600 rounded-lg text-red-400 text-sm">
            {error}
          </div>
        )}
      </div>

      {/* Scan Results */}
      {results.length > 0 && (
        <div className="space-y-4">
          <h2 className="text-xl font-semibold text-gray-100">Scan Results</h2>
          {results.map((result, idx) => (
            <div key={idx} className="bg-gray-900 border border-gray-800 rounded-lg p-4">
              <div className="flex items-start justify-between mb-3">
                <div>
                  <div className="font-semibold text-gray-100 mb-1">{result.target}</div>
                  <div className="text-xs text-gray-400">
                    {result.scanner} • {new Date(result.timestamp).toLocaleString()}
                  </div>
                </div>
                <span className={`text-sm font-semibold ${getStatusColor(result.status)}`}>
                  {result.status.toUpperCase()}
                </span>
              </div>

              {result.findings.length > 0 ? (
                <div className="space-y-2">
                  <div className="text-sm text-gray-400 mb-2">
                    {result.findings.length} finding(s)
                  </div>
                  {result.findings.map(renderFinding)}
                </div>
              ) : (
                <div className="text-sm text-green-400">✓ No issues found</div>
              )}
            </div>
          ))}
        </div>
      )}

      {results.length === 0 && !error && (
        <div className="flex items-center justify-center flex-1">
          <div className="text-center text-gray-400">
            <div className="text-4xl mb-4">🔍</div>
            <p>No scans yet. Enter a path and click Scan to begin.</p>
          </div>
        </div>
      )}
    </div>
  );
}
