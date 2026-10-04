import { create } from "zustand"

export interface Message {
  id: string
  role: "user" | "assistant"
  content: string
  timestamp: Date
}

export interface Thread {
  // ⚠️ MUST be a UUID (db.rs::create_thread guarantees this).
  // Used directly as the gateway session_id — never put a user-readable
  // string here, or session_key collisions / PII leaks become possible.
  id: string
  agent_id: string
  title: string
  created_at: number
  last_active_at: number
}

interface ChatStore {
  activeThreadId: string | null
  threads: Thread[]
  messages: Message[]
  isLoading: boolean

  setThreads: (threads: Thread[]) => void
  setActiveThread: (id: string, messages: Message[]) => void

  // Append a full message to the active thread.
  // Drops silently if threadId !== activeThreadId — third line of defense
  // for the streaming-race when the user switches threads mid-stream
  // (see plan §4.3 / §5). First two layers live in App.tsx handleSend.
  addMessage: (threadId: string, message: Message) => void

  // Mutate an existing message in place (used by SSE delta accumulator).
  // Same active-thread guard as addMessage. Without this guard, streaming
  // chunks would leak into the wrong ChatBox.
  updateMessage: (
    threadId: string,
    messageId: string,
    patch: Partial<Message>
  ) => void

  upsertThread: (thread: Thread) => void
  removeThread: (id: string) => void
  renameThread: (id: string, title: string) => void

  // Local mirror of db.save_message's "UPDATE threads SET last_active_at = now".
  // Called from handleSend so the sidebar reorders immediately; db is the real
  // SoT and the next list_threads reload will overwrite the client-side value.
  // Uses seconds (Math.floor(Date.now()/1000)) to match db.rs's chrono::Utc::now().timestamp()
  // — keeps the column's unit consistent so any future "new Date(t*1000)" still works.
  touchThread: (threadId: string) => void

  setLoading: (loading: boolean) => void
}

export const useChatStore = create<ChatStore>((set) => ({
  activeThreadId: null,
  threads: [],
  messages: [],
  isLoading: false,

  setThreads: (threads) => set({ threads }),

  setActiveThread: (id, messages) => set({ activeThreadId: id, messages }),

  addMessage: (threadId, message) =>
    set((state) => {
      if (state.activeThreadId !== threadId) return state
      return { messages: [...state.messages, message] }
    }),

  updateMessage: (threadId, messageId, patch) =>
    set((state) => {
      if (state.activeThreadId !== threadId) return state
      return {
        messages: state.messages.map((m) =>
          m.id === messageId ? { ...m, ...patch } : m
        ),
      }
    }),

  upsertThread: (thread) =>
    set((state) => {
      const idx = state.threads.findIndex((t) => t.id === thread.id)
      if (idx >= 0) {
        const next = [...state.threads]
        next[idx] = thread
        return { threads: next }
      }
      return { threads: [thread, ...state.threads] }
    }),

  removeThread: (id) =>
    set((state) => {
      const threads = state.threads.filter((t) => t.id !== id)
      if (state.activeThreadId !== id) return { threads }
      return { threads, activeThreadId: null, messages: [] }
    }),

  renameThread: (id, title) =>
    set((state) => {
      const idx = state.threads.findIndex((t) => t.id === id)
      if (idx < 0) return state
      const next = [...state.threads]
      next[idx] = { ...next[idx], title }
      return { threads: next }
    }),

  touchThread: (threadId) =>
    set((state) => {
      const idx = state.threads.findIndex((t) => t.id === threadId)
      if (idx < 0) return state
      const next = [...state.threads]
      next[idx] = { ...next[idx], last_active_at: Math.floor(Date.now() / 1000) }
      next.sort((a, b) => b.last_active_at - a.last_active_at)
      return { threads: next }
    }),

  setLoading: (loading) => set({ isLoading: loading }),
}))
