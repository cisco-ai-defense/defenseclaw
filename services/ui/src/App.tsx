import { useEffect, useState } from "react"
import { ChatBox } from "./components/ChatBox"
import { AgentSidebar } from "./components/AgentSidebar"
import { TitleBar } from "./components/TitleBar"
import { useChatStore, type Message, type Thread } from "./store/chatStore"
import { toast } from "sonner"
import { useAgentStream } from "./hooks/useAgentStream"

const MAIN_AGENT_ID = "main"

const STORAGE_KEY = "defenseclaw-threads"

function loadThreadsFromStorage(): { threads: Thread[]; messages: Record<string, Message[]> } {
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    if (raw) return JSON.parse(raw)
  } catch { /* ignore */ }
  return { threads: [], messages: {} }
}

function saveThreadsToStorage(threads: Thread[], allMessages: Record<string, Message[]>) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify({ threads, messages: allMessages }))
}

function App() {
  const {
    activeThreadId,
    threads,
    messages,
    isLoading,
    setThreads,
    setActiveThread,
    addMessage,
    upsertThread,
    removeThread,
    renameThread,
    touchThread,
  } = useChatStore()

  const [input, setInput] = useState("")
  const [viewMode, setViewMode] = useState<"chat">("chat")
  const [bootstrapped, setBootstrapped] = useState(false)
  const [threadMessages] = useState<Record<string, Message[]>>({})
  const { processAgentStream, stopStream } = useAgentStream()

  // Bootstrap: load threads from localStorage
  useEffect(() => {
    const stored = loadThreadsFromStorage()

    if (stored.threads.length === 0) {
      const now = Math.floor(Date.now() / 1000)
      const t: Thread = {
        id: crypto.randomUUID(),
        agent_id: MAIN_AGENT_ID,
        title: "New chat",
        created_at: now,
        last_active_at: now,
      }
      setThreads([t])
      setActiveThread(t.id, [])
    } else {
      setThreads(stored.threads)
      const head = stored.threads[0]
      const msgs = (stored.messages[head.id] || []).map((m: Message) => ({
        ...m,
        timestamp: new Date(m.timestamp),
      }))
      setActiveThread(head.id, msgs)
      Object.assign(threadMessages, stored.messages)
    }
    setBootstrapped(true)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  // Auto-save threads + messages to localStorage
  useEffect(() => {
    if (!bootstrapped) return
    if (activeThreadId) {
      threadMessages[activeThreadId] = messages
    }
    saveThreadsToStorage(threads, threadMessages)
  }, [threads, messages, activeThreadId, bootstrapped, threadMessages])

  const handleThreadSelect = async (_agentId: string, threadId: string) => {
    if (threadId === activeThreadId) return
    if (activeThreadId) {
      threadMessages[activeThreadId] = messages
    }
    const stored = threadMessages[threadId] || []
    setActiveThread(threadId, stored.map((m: Message) => ({ ...m, timestamp: new Date(m.timestamp) })))
  }

  const handleCreateThread = async () => {
    const now = Math.floor(Date.now() / 1000)
    const t: Thread = {
      id: crypto.randomUUID(),
      agent_id: MAIN_AGENT_ID,
      title: `Chat ${threads.length + 1}`,
      created_at: now,
      last_active_at: now,
    }
    upsertThread(t)
    setActiveThread(t.id, [])
  }

  const handleDeleteThread = async (threadId: string) => {
    if (!confirm("Delete this thread?")) return
    delete threadMessages[threadId]
    removeThread(threadId)

    if (activeThreadId === threadId) {
      const remaining = useChatStore.getState().threads.filter((t) => t.agent_id === MAIN_AGENT_ID)
      if (remaining.length > 0) {
        await handleThreadSelect(MAIN_AGENT_ID, remaining[0].id)
      } else {
        await handleCreateThread()
      }
    }
  }

  const handleRenameThread = async (threadId: string, title: string) => {
    renameThread(threadId, title)
  }

  const sendDisabled = isLoading || !bootstrapped

  const handleSend = async () => {
    if (sendDisabled || !input.trim()) return
    if (!activeThreadId) {
      toast.error("No active thread")
      return
    }

    const threadIdAtSendTime = activeThreadId
    const userMessage = input.trim()
    setInput("")

    const userMessageId = crypto.randomUUID()
    addMessage(threadIdAtSendTime, {
      id: userMessageId,
      role: "user",
      content: userMessage,
      timestamp: new Date(),
    })
    touchThread(threadIdAtSendTime)

    await processAgentStream(userMessage, userMessageId, threadIdAtSendTime)
  }

  const mainThreads = threads.filter((t) => t.agent_id === MAIN_AGENT_ID)

  return (
    <div className="flex flex-col h-screen bg-gradient-to-br from-slate-50 to-blue-50">
      <TitleBar
        title="MyAgent"
        onNavigate={(view) => setViewMode(view as "chat")}
        currentView={viewMode}
      />

      <main className="flex-1 overflow-hidden flex">
        <AgentSidebar
          mainAgentId={MAIN_AGENT_ID}
          threads={mainThreads}
          activeThreadId={activeThreadId ?? undefined}
          onThreadSelect={handleThreadSelect}
          onCreateThread={handleCreateThread}
          onDeleteThread={handleDeleteThread}
          onRenameThread={handleRenameThread}
        />

        <div className="flex-1 overflow-hidden flex flex-col">
          <div className="h-full max-w-5xl mx-auto w-full px-6 py-6">
            <ChatBox
              messages={messages}
              input={input}
              onInputChange={setInput}
              onSend={handleSend}
              onStop={stopStream}
              isLoading={sendDisabled}
            />
          </div>
        </div>
      </main>

      <footer className="bg-white border-t border-gray-200 py-3">
        <div className="max-w-7xl mx-auto px-6">
          <p className="text-xs text-gray-500 text-center">
            MyAgent IT Governed Mode | Powered by LiteLLM + Semantic Router
          </p>
        </div>
      </footer>
    </div>
  )
}

export default App
