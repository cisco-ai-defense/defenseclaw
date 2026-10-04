# DefenseClaw UI

Web-based chat UI for DefenseClaw IT Governed mode. Forked from Circuit Pulse desktop UI, rewired to use DefenseClaw's LiteLLM proxy.

## Status: WIP

Forked from `circuit-pulse-rust/services/desktop/`. Needs the following changes to be fully functional:

### Done
- [x] Copied source files
- [x] Removed Tauri from package.json dependencies
- [x] Rewrote `useAgentStream.ts` to use OpenAI Responses API streaming against LiteLLM:4001
- [x] Stubbed `utils/tauri.ts` to always return false

### TODO
- [ ] Remove Tauri imports from `App.tsx` — replace `invoke()` calls with local state/localStorage
- [ ] Remove Tauri imports from `AgentSidebar.tsx` — use `window.confirm()` instead of Tauri dialog
- [ ] Remove Tauri imports from `ErrorBoundaryTest.tsx`
- [ ] Remove `consoleLogger.ts` (uses Tauri fs/path)
- [ ] Remove A2UI dependencies (`@a2ui/*`) or stub them
- [ ] Rebrand: "CIRCUIT Pulse" → "DefenseClaw" in TitleBar, Sidebar
- [ ] Add `.env` config for `VITE_LITELLM_URL` and `VITE_LITELLM_KEY`
- [ ] Thread persistence via localStorage (replace Tauri SQLite)
- [ ] Add MCP tool rendering in chat (show tool calls/results inline)
- [ ] Test end-to-end with LiteLLM proxy

## Architecture

```
Browser (React + Vite + TailwindCSS)
  │
  │ fetch() with SSE streaming
  ▼
LiteLLM Proxy (port 4001)
  ├── /v1/responses (streaming)
  ├── /v1/models
  └── /mcp/ (MCP tool gateway)
```

## Dev Setup

```bash
cd services/ui
npm install    # or pnpm install
npm run dev    # starts on http://localhost:5173
```

Set environment:
```bash
# .env.local
VITE_LITELLM_URL=http://127.0.0.1:4001
VITE_LITELLM_KEY=<DEFENSECLAW_GATEWAY_TOKEN>
```

## Source Structure

```
src/
  App.tsx                    # Main layout
  components/
    ChatBox.tsx              # Chat messages + input
    AgentSidebar.tsx         # Agent/thread sidebar
    TitleBar.tsx             # Top navigation bar
  hooks/
    useAgentStream.ts        # LLM streaming (rewired to LiteLLM)
  store/
    chatStore.ts             # Zustand state management
  utils/
    tauri.ts                 # Stubbed (always false)
```
