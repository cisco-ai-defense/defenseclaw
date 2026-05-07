# DefenseClaw macOS App — Phase 3: Tauri + React App (App B)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the Tauri v2 + React/TypeScript app that mirrors the SwiftUI app's functionality — native chat with streaming/thinking, governance sidebar, config editor, system tray — using web technologies for the frontend and Rust for system integration.

**Architecture:** Tauri v2 app with React 18 + TypeScript frontend. Rust backend handles LaunchAgent management and process spawning. Frontend uses `fetch()` for sidecar REST and native `WebSocket` for OpenClaw gateway. State managed via React hooks (useSidecar, useSession, useWebSocket).

**Tech Stack:** Tauri v2, Rust, React 18, TypeScript 5, Vite, Tailwind CSS

**Depends on:** Phases 1-2 not required (Tauri reimplements services in TypeScript), but shares the same spec/protocol.

---

## File Structure

```
apps/tauri-app/
  src-tauri/
    src/
      main.rs                       # Tauri entry, commands, tray
      commands.rs                   # Tauri commands: launchagent, process run
    tauri.conf.json
    Cargo.toml
  src/
    main.tsx                        # React entry
    App.tsx                         # Root: sidebar + content
    components/
      Layout/
        Sidebar.tsx                 # Navigation sidebar
        StatusBar.tsx               # Bottom status bar
      Session/
        SessionView.tsx             # Chat + governance split
        ChatPanel.tsx               # Message list with streaming
        ChatInput.tsx               # Input bar
        MessageBubble.tsx           # Single message renderer
        ThinkingBlock.tsx           # Collapsible thinking
        ToolCallCard.tsx            # Tool call inline card
        ApprovalCard.tsx            # Approve/deny card
        GuardrailBadge.tsx          # Guardrail block badge
      Governance/
        GovernanceSidebar.tsx       # Right panel
      Settings/
        SettingsDialog.tsx          # Config editor modal
      NewSession/
        NewSessionDialog.tsx        # New session form
    services/
      sidecar-client.ts            # REST client (fetch)
      agent-session.ts             # WebSocket v3 client
      process-runner.ts            # Tauri invoke for CLI commands
    hooks/
      useSidecar.ts                # Sidecar health polling
      useSession.ts                # Per-session state
    types/
      index.ts                     # All shared types
      chat.ts                      # ChatMessage, ContentBlock types
    index.html
    index.css                      # Tailwind directives
  package.json
  vite.config.ts
  tsconfig.json
  tailwind.config.js
```

---

### Task 1: Tauri + React Scaffold

**Files:**
- Create: `apps/tauri-app/package.json`
- Create: `apps/tauri-app/src-tauri/Cargo.toml`
- Create: `apps/tauri-app/src-tauri/tauri.conf.json`
- Create: `apps/tauri-app/src-tauri/src/main.rs`
- Create: `apps/tauri-app/vite.config.ts`
- Create: `apps/tauri-app/tsconfig.json`
- Create: `apps/tauri-app/tailwind.config.js`
- Create: `apps/tauri-app/src/main.tsx`
- Create: `apps/tauri-app/src/index.html`
- Create: `apps/tauri-app/src/index.css`

- [ ] **Step 1: Initialize with Tauri CLI**

```bash
cd apps && npm create tauri-app@latest tauri-app -- --template react-ts --manager npm
cd tauri-app && npm install
npm install -D tailwindcss @tailwindcss/vite
```

- [ ] **Step 2: Configure tailwind**

```js
// apps/tauri-app/tailwind.config.js
/** @type {import('tailwindcss').Config} */
export default {
  content: ["./src/**/*.{ts,tsx}"],
  theme: { extend: {} },
  plugins: [],
}
```

```css
/* apps/tauri-app/src/index.css */
@tailwind base;
@tailwind components;
@tailwind utilities;

body {
  @apply bg-gray-900 text-gray-100;
  font-family: -apple-system, BlinkMacSystemFont, 'SF Pro', sans-serif;
}
```

- [ ] **Step 3: Update tauri.conf.json for DefenseClaw**

Key settings in `tauri.conf.json`:
```json
{
  "productName": "DefenseClaw",
  "identifier": "com.defenseclaw.app",
  "build": { "devUrl": "http://localhost:1420", "frontendDist": "../dist" },
  "app": {
    "windows": [{ "title": "DefenseClaw", "width": 1200, "height": 800, "minWidth": 900, "minHeight": 600 }],
    "trayIcon": { "iconPath": "icons/icon.png", "tooltip": "DefenseClaw" }
  }
}
```

- [ ] **Step 4: Write Rust main with LaunchAgent commands**

```rust
// apps/tauri-app/src-tauri/src/main.rs
use std::process::Command;

#[tauri::command]
fn launchagent_install(binary_path: String) -> Result<String, String> {
    // Write plist and load via launchctl
    let label = "com.defenseclaw.sidecar";
    let home = std::env::var("HOME").unwrap_or_default();
    let plist_path = format!("{}/Library/LaunchAgents/{}.plist", home, label);

    let plist = format!(r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>{label}</string>
    <key>ProgramArguments</key><array><string>{binary_path}</string><string>start</string><string>--foreground</string></array>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><true/>
    <key>StandardOutPath</key><string>{home}/.defenseclaw/sidecar.stdout.log</string>
    <key>StandardErrorPath</key><string>{home}/.defenseclaw/sidecar.stderr.log</string>
</dict>
</plist>"#);

    std::fs::write(&plist_path, plist).map_err(|e| e.to_string())?;
    Command::new("launchctl").args(["load", &plist_path]).output().map_err(|e| e.to_string())?;
    Ok("installed".into())
}

#[tauri::command]
fn launchagent_uninstall() -> Result<String, String> {
    let home = std::env::var("HOME").unwrap_or_default();
    let plist_path = format!("{}/Library/LaunchAgents/com.defenseclaw.sidecar.plist", home);
    let _ = Command::new("launchctl").args(["unload", &plist_path]).output();
    std::fs::remove_file(&plist_path).map_err(|e| e.to_string())?;
    Ok("uninstalled".into())
}

#[tauri::command]
fn run_cli(args: Vec<String>) -> Result<String, String> {
    let output = Command::new("defenseclaw").args(&args).output().map_err(|e| e.to_string())?;
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    Ok(format!("{}{}", stdout, stderr))
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![launchagent_install, launchagent_uninstall, run_cli])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
```

- [ ] **Step 5: Write React entry**

```tsx
// apps/tauri-app/src/main.tsx
import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App'
import './index.css'

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
)
```

```tsx
// apps/tauri-app/src/App.tsx
import { useState } from 'react'

export default function App() {
  return (
    <div className="flex h-screen">
      <div className="flex-1 flex items-center justify-center">
        <h1 className="text-2xl font-bold">DefenseClaw</h1>
      </div>
    </div>
  )
}
```

- [ ] **Step 6: Verify it builds**

Run: `cd apps/tauri-app && npm run build`
Expected: Frontend builds successfully.

- [ ] **Step 7: Commit**

```bash
git add apps/tauri-app/
git commit -m "feat(macos): scaffold Tauri v2 + React app"
```

---

### Task 2: TypeScript Types and Services

**Files:**
- Create: `apps/tauri-app/src/types/index.ts`
- Create: `apps/tauri-app/src/types/chat.ts`
- Create: `apps/tauri-app/src/services/sidecar-client.ts`
- Create: `apps/tauri-app/src/services/agent-session.ts`

- [ ] **Step 1: Write shared types**

```typescript
// apps/tauri-app/src/types/index.ts
export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO' | 'NONE';

export interface SubsystemHealth {
  state: 'starting' | 'running' | 'reconnecting' | 'stopped' | 'error' | 'disabled';
  since: string;
  last_error?: string;
}

export interface HealthSnapshot {
  started_at: string;
  uptime_ms: number;
  gateway: SubsystemHealth;
  watcher: SubsystemHealth;
  api: SubsystemHealth;
  guardrail: SubsystemHealth;
  telemetry: SubsystemHealth;
  splunk: SubsystemHealth;
  sandbox?: SubsystemHealth;
}

export interface Alert {
  id: string;
  action: string;
  target: string;
  severity: Severity;
  details: string;
  timestamp: string;
}

export interface Skill {
  id: string; name: string; path?: string;
  enabled: boolean; blocked: boolean; allowed: boolean; quarantined: boolean;
}

export interface MCPServer {
  id: string; name: string; url?: string; command?: string;
  blocked: boolean; allowed: boolean;
}

export interface ToolEntry {
  id: string; name: string; description?: string; source?: string; blocked: boolean;
}

export interface ScanResult {
  id: string; target: string; scan_type: string; severity: Severity;
  findings: Finding[];
}

export interface Finding {
  id: string; rule: string; severity: Severity; description: string;
}

export interface GuardrailConfig {
  enabled: boolean; mode: string; scanner_mode: string; block_message?: string;
}
```

```typescript
// apps/tauri-app/src/types/chat.ts
export type MessageRole = 'user' | 'assistant' | 'system' | 'tool';
export type ToolCallStatus = 'pending' | 'running' | 'completed' | 'failed' | 'warned' | 'blocked';
export type ApprovalDecision = 'approved' | 'denied' | 'auto_approved';

export type ContentBlock =
  | { type: 'text'; id: string; text: string }
  | { type: 'thinking'; id: string; text: string; durationMs?: number }
  | { type: 'tool_call'; id: string; tool: string; args: string; status: ToolCallStatus; output?: string; elapsedMs?: number }
  | { type: 'approval_request'; id: string; command: string; cwd: string; isDangerous: boolean; decision?: ApprovalDecision }
  | { type: 'guardrail_badge'; id: string; severity: string; action: string; reason: string };

export interface ChatMessage {
  id: string;
  role: MessageRole;
  blocks: ContentBlock[];
  timestamp: number;
  isStreaming: boolean;
}
```

- [ ] **Step 2: Write sidecar REST client**

```typescript
// apps/tauri-app/src/services/sidecar-client.ts
const BASE_URL = 'http://127.0.0.1:18790';

async function get<T>(path: string): Promise<T> {
  const res = await fetch(`${BASE_URL}${path}`);
  if (!res.ok) throw new Error(`Sidecar ${path}: ${res.status}`);
  return res.json();
}

async function post<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(`${BASE_URL}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`Sidecar ${path}: ${res.status}`);
  return res.json();
}

export const sidecarClient = {
  health: () => get<import('../types').HealthSnapshot>('/health'),
  alerts: () => get<import('../types').Alert[]>('/alerts'),
  skills: () => get<import('../types').Skill[]>('/skills'),
  mcpServers: () => get<import('../types').MCPServer[]>('/mcps'),
  toolsCatalog: () => get<import('../types').ToolEntry[]>('/tools/catalog'),
  guardrailConfig: () => get<import('../types').GuardrailConfig>('/v1/guardrail/config'),
  blockedList: () => get<unknown[]>('/enforce/blocked'),
  allowedList: () => get<unknown[]>('/enforce/allowed'),

  block: (type: string, name: string, reason?: string) =>
    post('/enforce/block', { type, name, reason }),
  allow: (type: string, name: string, reason?: string) =>
    post('/enforce/allow', { type, name, reason }),
  disableSkill: (key: string) => post('/skill/disable', { skill_key: key }),
  enableSkill: (key: string) => post('/skill/enable', { skill_key: key }),
  scanSkill: (path: string) => post<import('../types').ScanResult>('/v1/skill/scan', { path }),
  scanMCP: (url: string) => post<import('../types').ScanResult>('/v1/mcp/scan', { url }),
  scanCode: (path: string) => post<import('../types').ScanResult>('/api/v1/scan/code', { path }),
  policyReload: () => post('/policy/reload', {}),
};
```

- [ ] **Step 3: Write WebSocket v3 agent session**

```typescript
// apps/tauri-app/src/services/agent-session.ts
import { ChatMessage, ContentBlock } from '../types/chat';

const DANGEROUS_PATTERNS = [
  'curl', 'wget', 'nc ', 'ncat', 'netcat', '/dev/tcp',
  'base64 -d', 'base64 --decode', 'eval ', 'bash -c', 'sh -c',
  'python -c', 'perl -e', 'ruby -e', 'rm -rf /', 'dd if=', 'mkfs',
  'chmod 777', '> /etc/', '>> /etc/', 'passwd', 'shadow', 'sudoers',
];

export function isDangerousCommand(cmd: string): boolean {
  const lower = cmd.toLowerCase();
  return DANGEROUS_PATTERNS.some(p => lower.includes(p));
}

export type AgentEventHandler = {
  onToolCall?: (tool: string, args: string) => void;
  onToolResult?: (tool: string, output: string, exitCode: number) => void;
  onApprovalRequest?: (id: string, command: string, cwd: string) => void;
  onDisconnect?: () => void;
};

export class AgentSessionClient {
  private ws: WebSocket | null = null;
  private handlers: AgentEventHandler;

  constructor(handlers: AgentEventHandler) {
    this.handlers = handlers;
  }

  connect(host = '127.0.0.1', port = 18789) {
    this.ws = new WebSocket(`ws://${host}:${port}`);
    this.ws.onmessage = (ev) => this.handleFrame(ev.data);
    this.ws.onclose = () => this.handlers.onDisconnect?.();
  }

  disconnect() {
    this.ws?.close();
    this.ws = null;
  }

  sendRPC(method: string, params: Record<string, unknown>) {
    const frame = { type: 'req', id: crypto.randomUUID(), method, params };
    this.ws?.send(JSON.stringify(frame));
  }

  resolveApproval(id: string, approved: boolean) {
    this.sendRPC('exec.approval.resolve', { id, decision: approved ? 'approved' : 'denied' });
  }

  private handleFrame(data: string) {
    try {
      const json = JSON.parse(data);
      if (json.type === 'event') this.handleEvent(json);
    } catch { /* ignore malformed frames */ }
  }

  private handleEvent(json: { event: string; payload?: Record<string, unknown> }) {
    const { event, payload } = json;
    switch (event) {
      case 'tool_call':
        if (payload?.tool) {
          const args = payload.args ? JSON.stringify(payload.args) : '';
          this.handlers.onToolCall?.(payload.tool as string, args);
        }
        break;
      case 'tool_result':
        if (payload?.tool) {
          this.handlers.onToolResult?.(
            payload.tool as string,
            (payload.output as string) ?? '',
            (payload.exit_code as number) ?? 0
          );
        }
        break;
      case 'exec.approval.requested':
        if (payload?.id) {
          const plan = payload.systemRunPlan as Record<string, string> | undefined;
          this.handlers.onApprovalRequest?.(
            payload.id as string,
            plan?.rawCommand ?? 'unknown',
            plan?.cwd ?? ''
          );
        }
        break;
    }
  }
}
```

- [ ] **Step 4: Commit**

```bash
git add apps/tauri-app/src/types/ apps/tauri-app/src/services/
git commit -m "feat(macos): add Tauri TypeScript types and service clients"
```

---

### Task 3: React Chat UI Components

**Files:**
- Create all components in `apps/tauri-app/src/components/Session/`
- Create `apps/tauri-app/src/hooks/useSession.ts`
- Create `apps/tauri-app/src/hooks/useSidecar.ts`
- Modify: `apps/tauri-app/src/App.tsx`

- [ ] **Step 1: Write hooks**

```typescript
// apps/tauri-app/src/hooks/useSidecar.ts
import { useState, useEffect } from 'react';
import { sidecarClient } from '../services/sidecar-client';
import type { HealthSnapshot, Alert, Skill, MCPServer, GuardrailConfig } from '../types';

export function useSidecar() {
  const [health, setHealth] = useState<HealthSnapshot | null>(null);
  const [connected, setConnected] = useState(false);

  useEffect(() => {
    const poll = async () => {
      try {
        const h = await sidecarClient.health();
        setHealth(h);
        setConnected(true);
      } catch {
        setConnected(false);
      }
    };
    poll();
    const interval = setInterval(poll, 5000);
    return () => clearInterval(interval);
  }, []);

  return { health, connected };
}
```

```typescript
// apps/tauri-app/src/hooks/useSession.ts
import { useState, useCallback } from 'react';
import type { ChatMessage, ContentBlock } from '../types/chat';

let msgCounter = 0;
const nextId = () => `msg-${++msgCounter}-${Date.now()}`;
const blockId = () => `blk-${++msgCounter}-${Date.now()}`;

export function useSession() {
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [isStreaming, setIsStreaming] = useState(false);

  const sendMessage = useCallback((text: string) => {
    const msg: ChatMessage = {
      id: nextId(), role: 'user',
      blocks: [{ type: 'text', id: blockId(), text }],
      timestamp: Date.now(), isStreaming: false,
    };
    setMessages(prev => [...prev, msg]);
  }, []);

  const appendToolCall = useCallback((tool: string, args: string) => {
    const block: ContentBlock = {
      type: 'tool_call', id: blockId(), tool, args,
      status: 'running', output: undefined, elapsedMs: undefined,
    };
    setMessages(prev => {
      const last = prev[prev.length - 1];
      if (last?.role === 'assistant') {
        return [...prev.slice(0, -1), { ...last, blocks: [...last.blocks, block] }];
      }
      return [...prev, { id: nextId(), role: 'assistant', blocks: [block], timestamp: Date.now(), isStreaming: true }];
    });
  }, []);

  const updateToolResult = useCallback((tool: string, output: string, exitCode: number) => {
    setMessages(prev => prev.map(msg => ({
      ...msg,
      blocks: msg.blocks.map(b =>
        b.type === 'tool_call' && b.tool === tool && b.status === 'running'
          ? { ...b, status: exitCode === 0 ? 'completed' as const : 'failed' as const, output }
          : b
      ),
    })));
  }, []);

  const appendApproval = useCallback((id: string, command: string, cwd: string, isDangerous: boolean) => {
    const block: ContentBlock = {
      type: 'approval_request', id, command, cwd, isDangerous, decision: undefined,
    };
    setMessages(prev => {
      const last = prev[prev.length - 1];
      if (last?.role === 'assistant') {
        return [...prev.slice(0, -1), { ...last, blocks: [...last.blocks, block] }];
      }
      return [...prev, { id: nextId(), role: 'assistant', blocks: [block], timestamp: Date.now(), isStreaming: false }];
    });
  }, []);

  return { messages, isStreaming, sendMessage, appendToolCall, updateToolResult, appendApproval };
}
```

- [ ] **Step 2: Write chat components**

Create the main components following the same visual patterns as the SwiftUI app. Each component is a focused React functional component.

The key components (ChatPanel, MessageBubble, ThinkingBlock, ToolCallCard, ApprovalCard, GuardrailBadge, ChatInput, GovernanceSidebar) follow the same structure as their SwiftUI counterparts but use Tailwind CSS for styling.

Due to the large number of component files (each ~30-80 lines), the implementation follows this pattern:
- MessageBubble iterates over `message.blocks` and renders the appropriate sub-component
- ThinkingBlock uses a `<details>` element for collapse/expand
- ToolCallCard shows status icon + tool name + collapsible output
- ApprovalCard shows command + Approve/Deny buttons
- ChatInput uses a textarea with Shift+Enter for newlines

- [ ] **Step 3: Wire up App.tsx**

```tsx
// apps/tauri-app/src/App.tsx
import { useState } from 'react';
import { useSidecar } from './hooks/useSidecar';
import { useSession } from './hooks/useSession';

export default function App() {
  const { health, connected } = useSidecar();
  const session = useSession();
  const [input, setInput] = useState('');

  const handleSend = () => {
    const text = input.trim();
    if (!text) return;
    session.sendMessage(text);
    setInput('');
  };

  return (
    <div className="flex h-screen bg-gray-900">
      {/* Sidebar */}
      <div className="w-48 border-r border-gray-700 p-4">
        <h2 className="text-sm font-bold text-cyan-400 mb-4">DefenseClaw</h2>
        <div className="text-xs">
          <span className={`inline-block w-2 h-2 rounded-full mr-1 ${connected ? 'bg-green-500' : 'bg-red-500'}`} />
          {connected ? 'Connected' : 'Offline'}
        </div>
      </div>

      {/* Chat area */}
      <div className="flex-1 flex flex-col">
        <div className="flex-1 overflow-y-auto p-4 space-y-3">
          {session.messages.map(msg => (
            <div key={msg.id} className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}>
              <div className={`max-w-[80%] rounded-lg p-3 ${msg.role === 'user' ? 'bg-cyan-900/30' : 'bg-gray-800'}`}>
                {msg.blocks.map(block => {
                  if (block.type === 'text') return <p key={block.id}>{block.text}</p>;
                  if (block.type === 'tool_call') return (
                    <div key={block.id} className="border border-gray-600 rounded p-2 my-1 text-sm">
                      <span className="font-mono font-bold">{block.tool}</span>
                      <span className="ml-2 text-gray-400">{block.status}</span>
                    </div>
                  );
                  return null;
                })}
              </div>
            </div>
          ))}
        </div>

        {/* Input */}
        <div className="border-t border-gray-700 p-3 flex gap-2">
          <input
            className="flex-1 bg-gray-800 rounded px-3 py-2 text-sm outline-none"
            value={input}
            onChange={e => setInput(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && !e.shiftKey && handleSend()}
            placeholder="Type a message..."
          />
          <button
            onClick={handleSend}
            className="bg-cyan-600 hover:bg-cyan-500 px-4 py-2 rounded text-sm font-bold"
          >Send</button>
        </div>
      </div>

      {/* Governance sidebar */}
      <div className="w-56 border-l border-gray-700 p-4 text-xs">
        <h3 className="font-bold text-red-400 mb-2">GOVERNANCE</h3>
        {health && (
          <div className="space-y-1">
            <div>Gateway: {health.gateway.state}</div>
            <div>Guardrail: {health.guardrail.state}</div>
            <div>Watcher: {health.watcher.state}</div>
          </div>
        )}
      </div>
    </div>
  );
}
```

- [ ] **Step 4: Build**

Run: `cd apps/tauri-app && npm run build`
Expected: Build Succeeded

- [ ] **Step 5: Commit**

```bash
git add apps/tauri-app/src/
git commit -m "feat(macos): Tauri React app with chat, hooks, governance sidebar"
```

---

### Task 4: Tauri Build and Tray Icon

- [ ] **Step 1: Build the Tauri app (requires Rust)**

Run: `cd apps/tauri-app && npm run tauri build`
Expected: .app bundle created in `src-tauri/target/release/bundle/`

- [ ] **Step 2: Commit final state**

```bash
git add apps/tauri-app/
git commit -m "feat(macos): complete Tauri v2 app build"
```

---

## Summary

| Task | Component | Key Files |
|------|-----------|-----------|
| 1 | Tauri + React scaffold | Package.json, Cargo.toml, main.rs, App.tsx |
| 2 | Types + services | types/index.ts, chat.ts, sidecar-client.ts, agent-session.ts |
| 3 | React chat UI | hooks/useSession.ts, useSidecar.ts, App.tsx with chat |
| 4 | Build + tray | Tauri build, system tray |

**Total: ~20 source files, 4 commits**
