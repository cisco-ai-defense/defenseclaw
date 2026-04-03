import { useState, useRef, useEffect } from 'react';
import { useSidecar } from '@/hooks/useSidecar';
import { useSession } from '@/hooks/useSession';
import type { ChatMessage, ContentBlock } from '@/types/chat';

function App() {
  const { health, error: healthError } = useSidecar();
  const { messages, isConnected, sendMessage, approveCommand } = useSession();
  const [inputValue, setInputValue] = useState('');
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

  const getHealthStatusColor = (status: string) => {
    switch (status) {
      case 'healthy':
        return 'text-green-400';
      case 'degraded':
        return 'text-yellow-400';
      case 'down':
        return 'text-red-400';
      default:
        return 'text-gray-400';
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

        <div className="flex-1 p-4">
          <div className="text-sm text-gray-400">Navigation placeholder</div>
        </div>
      </div>

      {/* Center Chat Area */}
      <div className="flex-1 flex flex-col">
        {/* Messages */}
        <div className="flex-1 overflow-y-auto p-4">
          {messages.length === 0 ? (
            <div className="flex items-center justify-center h-full">
              <div className="text-center">
                <h2 className="text-2xl font-bold text-cyan-400 mb-2">Welcome to DefenseClaw</h2>
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
          <div className="space-y-3">
            {/* Sidecar */}
            <div className="p-3 bg-gray-900 rounded-lg border border-gray-800">
              <div className="flex items-center justify-between mb-1">
                <span className="text-sm font-semibold">Sidecar</span>
                <span className={`text-xs ${getHealthStatusColor(health.sidecar.status)}`}>
                  {health.sidecar.status}
                </span>
              </div>
              {health.sidecar.message && (
                <p className="text-xs text-gray-400">{health.sidecar.message}</p>
              )}
            </div>

            {/* Gateway */}
            <div className="p-3 bg-gray-900 rounded-lg border border-gray-800">
              <div className="flex items-center justify-between mb-1">
                <span className="text-sm font-semibold">Gateway</span>
                <span className={`text-xs ${getHealthStatusColor(health.gateway.status)}`}>
                  {health.gateway.status}
                </span>
              </div>
              {health.gateway.message && (
                <p className="text-xs text-gray-400">{health.gateway.message}</p>
              )}
            </div>

            {/* Scanners */}
            <div className="p-3 bg-gray-900 rounded-lg border border-gray-800">
              <div className="flex items-center justify-between mb-1">
                <span className="text-sm font-semibold">Scanners</span>
                <span className={`text-xs ${getHealthStatusColor(health.scanners.status)}`}>
                  {health.scanners.status}
                </span>
              </div>
              {health.scanners.message && (
                <p className="text-xs text-gray-400">{health.scanners.message}</p>
              )}
            </div>

            {/* Sandbox (optional) */}
            {health.sandbox && (
              <div className="p-3 bg-gray-900 rounded-lg border border-gray-800">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-sm font-semibold">Sandbox</span>
                  <span className={`text-xs ${getHealthStatusColor(health.sandbox.status)}`}>
                    {health.sandbox.status}
                  </span>
                </div>
                {health.sandbox.message && (
                  <p className="text-xs text-gray-400">{health.sandbox.message}</p>
                )}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

export default App;
