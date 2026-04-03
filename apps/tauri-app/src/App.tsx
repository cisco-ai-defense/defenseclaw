import { useState, useRef, useEffect } from 'react';
import { useSidecar } from '@/hooks/useSidecar';
import { useSession } from '@/hooks/useSession';
import type { ChatMessage, ContentBlock } from '@/types/chat';
import { ScanPage } from '@/components/ScanPage';
import { PolicyPage } from '@/components/PolicyPage';
import { SettingsPage } from '@/components/SettingsPage';

type Page = 'chat' | 'scan' | 'policy' | 'settings';

function App() {
  const { health, error: healthError } = useSidecar();
  const { messages, isConnected, sendMessage, approveCommand } = useSession();
  const [inputValue, setInputValue] = useState('');
  const [currentPage, setCurrentPage] = useState<Page>('chat');
  const messagesEndRef = useRef<HTMLDivElement>(null);

  // Auto-scroll to bottom when messages change
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!inputValue.trim()) return;

    sendMessage(inputValue);
    setInputValue('');
  };

  const renderContentBlock = (block: ContentBlock) => {
    switch (block.type) {
      case 'text':
        return (
          <div key={block.id} className="text-gray-100">
            {block.text}
          </div>
        );

      case 'thinking':
        return (
          <div key={block.id} className="text-gray-400 italic">
            <span className="text-cyan-400">💭</span> {block.text}
            {block.durationMs && <span className="ml-2 text-xs">({block.durationMs}ms)</span>}
          </div>
        );

      case 'tool_call':
        return (
          <div
            key={block.id}
            className={`border rounded-lg p-3 my-2 ${
              block.status === 'success'
                ? 'border-green-600 bg-green-950/30'
                : block.status === 'error'
                ? 'border-red-600 bg-red-950/30'
                : block.status === 'blocked'
                ? 'border-yellow-600 bg-yellow-950/30'
                : 'border-cyan-600 bg-cyan-950/30'
            }`}
          >
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm font-mono text-cyan-400">{block.tool}</span>
              <span className="text-xs text-gray-400">{block.status}</span>
            </div>
            <pre className="text-xs text-gray-300 overflow-x-auto">{block.args}</pre>
            {block.output && (
              <div className="mt-2 pt-2 border-t border-gray-700">
                <div className="text-xs text-gray-400">Output:</div>
                <pre className="text-xs text-gray-300 mt-1 overflow-x-auto">{block.output}</pre>
              </div>
            )}
            {block.elapsedMs && <div className="text-xs text-gray-500 mt-1">{block.elapsedMs}ms</div>}
          </div>
        );

      case 'approval_request':
        return (
          <div
            key={block.id}
            className={`border rounded-lg p-3 my-2 ${
              block.isDangerous ? 'border-red-600 bg-red-950/30' : 'border-yellow-600 bg-yellow-950/30'
            }`}
          >
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm font-semibold text-yellow-400">
                {block.isDangerous ? '⚠️ Dangerous Command' : '⚠️ Approval Required'}
              </span>
              {block.decision && (
                <span
                  className={`text-xs ${
                    block.decision === 'approved' ? 'text-green-400' : 'text-red-400'
                  }`}
                >
                  {block.decision}
                </span>
              )}
            </div>
            <pre className="text-sm text-gray-200 mb-2">{block.command}</pre>
            <div className="text-xs text-gray-400 mb-3">Working directory: {block.cwd}</div>
            {!block.decision && (
              <div className="flex gap-2">
                <button
                  onClick={() => approveCommand(block.id, 'approved')}
                  className="px-3 py-1 text-sm bg-green-600 hover:bg-green-700 rounded"
                >
                  Approve
                </button>
                <button
                  onClick={() => approveCommand(block.id, 'rejected')}
                  className="px-3 py-1 text-sm bg-red-600 hover:bg-red-700 rounded"
                >
                  Reject
                </button>
              </div>
            )}
          </div>
        );

      case 'guardrail_badge':
        return (
          <div
            key={block.id}
            className="inline-flex items-center gap-2 px-2 py-1 rounded text-xs bg-purple-950/50 border border-purple-600 text-purple-300"
          >
            <span className="font-semibold">{block.severity}</span>
            <span>{block.action}</span>
            {block.reason && <span className="text-gray-400">- {block.reason}</span>}
          </div>
        );

      default:
        return null;
    }
  };

  const renderMessage = (message: ChatMessage) => {
    const isUser = message.role === 'user';

    return (
      <div key={message.id} className={`flex ${isUser ? 'justify-end' : 'justify-start'} mb-4`}>
        <div
          className={`max-w-2xl px-4 py-3 rounded-lg ${
            isUser ? 'bg-cyan-700 text-white' : 'bg-gray-800 text-gray-100'
          }`}
        >
          <div className="space-y-2">{message.content.map(renderContentBlock)}</div>
          <div className="text-xs text-gray-400 mt-2">
            {new Date(message.timestamp).toLocaleTimeString()}
          </div>
        </div>
      </div>
    );
  };

  const getHealthStateColor = (state: string) => {
    switch (state) {
      case 'running':
        return 'text-green-400';
      case 'reconnecting':
      case 'starting':
        return 'text-yellow-400';
      case 'stopped':
      case 'error':
        return 'text-red-400';
      case 'disabled':
        return 'text-gray-500';
      default:
        return 'text-gray-400';
    }
  };

  const getHealthStateBadge = (state: string) => {
    switch (state) {
      case 'running':
        return '●';
      case 'reconnecting':
      case 'starting':
        return '◐';
      case 'stopped':
      case 'error':
        return '○';
      case 'disabled':
        return '⊝';
      default:
        return '?';
    }
  };

  return (
    <div className="flex w-full h-full bg-gray-900 text-gray-100">
      {/* Left Sidebar */}
      <div className="w-64 bg-gray-950 border-r border-gray-800 flex flex-col">
        <div className="p-4 border-b border-gray-800">
          <h1 className="text-xl font-bold text-cyan-400">DefenseClaw</h1>
          <div className="mt-2 flex items-center gap-2">
            <div
              className={`w-2 h-2 rounded-full ${isConnected ? 'bg-green-400' : 'bg-red-400'}`}
            />
            <span className="text-xs text-gray-400">
              {isConnected ? 'Connected' : 'Disconnected'}
            </span>
          </div>
        </div>

        <nav className="flex-1 p-4">
          <div className="space-y-1">
            <button
              onClick={() => setCurrentPage('chat')}
              className={`w-full text-left px-3 py-2 rounded-lg transition ${
                currentPage === 'chat'
                  ? 'bg-cyan-600 text-white'
                  : 'text-gray-400 hover:bg-gray-900 hover:text-gray-200'
              }`}
            >
              <div className="flex items-center gap-2">
                <span>💬</span>
                <span className="font-medium">Chat</span>
              </div>
            </button>

            <button
              onClick={() => setCurrentPage('scan')}
              className={`w-full text-left px-3 py-2 rounded-lg transition ${
                currentPage === 'scan'
                  ? 'bg-cyan-600 text-white'
                  : 'text-gray-400 hover:bg-gray-900 hover:text-gray-200'
              }`}
            >
              <div className="flex items-center gap-2">
                <span>🔍</span>
                <span className="font-medium">Scan</span>
              </div>
            </button>

            <button
              onClick={() => setCurrentPage('policy')}
              className={`w-full text-left px-3 py-2 rounded-lg transition ${
                currentPage === 'policy'
                  ? 'bg-cyan-600 text-white'
                  : 'text-gray-400 hover:bg-gray-900 hover:text-gray-200'
              }`}
            >
              <div className="flex items-center gap-2">
                <span>📋</span>
                <span className="font-medium">Policy</span>
              </div>
            </button>

            <button
              onClick={() => setCurrentPage('settings')}
              className={`w-full text-left px-3 py-2 rounded-lg transition ${
                currentPage === 'settings'
                  ? 'bg-cyan-600 text-white'
                  : 'text-gray-400 hover:bg-gray-900 hover:text-gray-200'
              }`}
            >
              <div className="flex items-center gap-2">
                <span>⚙️</span>
                <span className="font-medium">Settings</span>
              </div>
            </button>
          </div>
        </nav>

        {/* Health Status at Bottom */}
        {health && (
          <div className="p-4 border-t border-gray-800">
            <div className="text-xs text-gray-400 mb-2 font-semibold">System Health</div>
            <div className="space-y-1">
              <div className="flex items-center justify-between text-xs">
                <span className="text-gray-400">Gateway</span>
                <span className={getHealthStateColor(health.gateway.state)}>
                  {getHealthStateBadge(health.gateway.state)} {health.gateway.state}
                </span>
              </div>
              <div className="flex items-center justify-between text-xs">
                <span className="text-gray-400">Watcher</span>
                <span className={getHealthStateColor(health.watcher.state)}>
                  {getHealthStateBadge(health.watcher.state)} {health.watcher.state}
                </span>
              </div>
              <div className="flex items-center justify-between text-xs">
                <span className="text-gray-400">API</span>
                <span className={getHealthStateColor(health.api.state)}>
                  {getHealthStateBadge(health.api.state)} {health.api.state}
                </span>
              </div>
              <div className="flex items-center justify-between text-xs">
                <span className="text-gray-400">Guardrail</span>
                <span className={getHealthStateColor(health.guardrail.state)}>
                  {getHealthStateBadge(health.guardrail.state)} {health.guardrail.state}
                </span>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Center Content Area */}
      <div className="flex-1 flex flex-col">
        {currentPage === 'chat' && (
          <>
            {/* Messages */}
            <div className="flex-1 overflow-y-auto p-4">
              {messages.length === 0 ? (
                <div className="flex items-center justify-center h-full">
                  <div className="text-center">
                    <h2 className="text-2xl font-bold text-cyan-400 mb-2">
                      Welcome to DefenseClaw
                    </h2>
                    <p className="text-gray-400">Start a conversation with your AI agent</p>
                  </div>
                </div>
              ) : (
                <div>
                  {messages.map(renderMessage)}
                  <div ref={messagesEndRef} />
                </div>
              )}
            </div>

            {/* Input Bar */}
            <div className="border-t border-gray-800 p-4">
              <form onSubmit={handleSubmit} className="flex gap-2">
                <input
                  type="text"
                  value={inputValue}
                  onChange={(e) => setInputValue(e.target.value)}
                  placeholder="Type your message..."
                  className="flex-1 px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg focus:outline-none focus:ring-2 focus:ring-cyan-600 text-gray-100"
                  disabled={!isConnected}
                />
                <button
                  type="submit"
                  disabled={!isConnected || !inputValue.trim()}
                  className="px-6 py-2 bg-cyan-600 hover:bg-cyan-700 disabled:bg-gray-700 disabled:text-gray-500 rounded-lg font-medium transition"
                >
                  Send
                </button>
              </form>
            </div>
          </>
        )}

        {currentPage === 'scan' && <ScanPage />}
        {currentPage === 'policy' && <PolicyPage />}
        {currentPage === 'settings' && <SettingsPage />}
      </div>

      {/* Right Governance Sidebar */}
      <div className="w-80 bg-gray-950 border-l border-gray-800 p-4 overflow-y-auto">
        <h2 className="text-lg font-bold text-cyan-400 mb-4">GOVERNANCE</h2>

        {healthError && (
          <div className="mb-4 p-3 bg-red-950/50 border border-red-600 rounded-lg">
            <p className="text-sm text-red-400">Failed to connect to sidecar</p>
          </div>
        )}

        {health && (
          <>
            <div className="mb-4 p-3 bg-gray-900 rounded-lg border border-gray-800">
              <div className="text-xs text-gray-400 mb-2">System Uptime</div>
              <div className="text-lg font-mono text-cyan-400">
                {Math.floor(health.uptime_ms / 1000 / 60)}m {Math.floor((health.uptime_ms / 1000) % 60)}s
              </div>
              <div className="text-xs text-gray-500 mt-1">
                Started: {new Date(health.started_at).toLocaleTimeString()}
              </div>
            </div>

            <div className="space-y-3">
              {/* Gateway */}
              <div className="p-3 bg-gray-900 rounded-lg border border-gray-800">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-sm font-semibold">Gateway</span>
                  <span className={`text-xs ${getHealthStateColor(health.gateway.state)}`}>
                    {getHealthStateBadge(health.gateway.state)} {health.gateway.state}
                  </span>
                </div>
                <div className="text-xs text-gray-400">
                  Since: {new Date(health.gateway.since).toLocaleTimeString()}
                </div>
              </div>

              {/* Watcher */}
              <div className="p-3 bg-gray-900 rounded-lg border border-gray-800">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-sm font-semibold">Watcher</span>
                  <span className={`text-xs ${getHealthStateColor(health.watcher.state)}`}>
                    {getHealthStateBadge(health.watcher.state)} {health.watcher.state}
                  </span>
                </div>
                <div className="text-xs text-gray-400">
                  Since: {new Date(health.watcher.since).toLocaleTimeString()}
                </div>
                {health.watcher.details && Object.keys(health.watcher.details).length > 0 && (
                  <div className="text-xs text-gray-500 mt-1">
                    {Object.entries(health.watcher.details).map(([key, value]) => (
                      <div key={key}>
                        {key}: {String(value)}
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* API */}
              <div className="p-3 bg-gray-900 rounded-lg border border-gray-800">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-sm font-semibold">API Server</span>
                  <span className={`text-xs ${getHealthStateColor(health.api.state)}`}>
                    {getHealthStateBadge(health.api.state)} {health.api.state}
                  </span>
                </div>
                <div className="text-xs text-gray-400">
                  Since: {new Date(health.api.since).toLocaleTimeString()}
                </div>
                {health.api.details && 'addr' in health.api.details && (
                  <div className="text-xs text-gray-500 mt-1 font-mono">
                    {String(health.api.details.addr)}
                  </div>
                )}
              </div>

              {/* Guardrail */}
              <div className="p-3 bg-gray-900 rounded-lg border border-gray-800">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-sm font-semibold">Guardrail</span>
                  <span className={`text-xs ${getHealthStateColor(health.guardrail.state)}`}>
                    {getHealthStateBadge(health.guardrail.state)} {health.guardrail.state}
                  </span>
                </div>
                <div className="text-xs text-gray-400">
                  Since: {new Date(health.guardrail.since).toLocaleTimeString()}
                </div>
              </div>

              {/* Telemetry */}
              <div className="p-3 bg-gray-900 rounded-lg border border-gray-800">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-sm font-semibold">Telemetry</span>
                  <span className={`text-xs ${getHealthStateColor(health.telemetry.state)}`}>
                    {getHealthStateBadge(health.telemetry.state)} {health.telemetry.state}
                  </span>
                </div>
                <div className="text-xs text-gray-400">
                  Since: {new Date(health.telemetry.since).toLocaleTimeString()}
                </div>
              </div>

              {/* Splunk */}
              <div className="p-3 bg-gray-900 rounded-lg border border-gray-800">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-sm font-semibold">Splunk HEC</span>
                  <span className={`text-xs ${getHealthStateColor(health.splunk.state)}`}>
                    {getHealthStateBadge(health.splunk.state)} {health.splunk.state}
                  </span>
                </div>
                <div className="text-xs text-gray-400">
                  Since: {new Date(health.splunk.since).toLocaleTimeString()}
                </div>
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  );
}

export default App;
