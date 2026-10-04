import { useState, useRef } from "react"
import { ChevronDown, ChevronRight, Plus, MessageSquare, X, Pencil } from "lucide-react"
// ChevronDown/Right still used for expand/collapse

import type { Thread } from "../store/chatStore"


interface AgentSidebarProps {
  mainAgentId: string
  threads: Thread[]
  activeThreadId?: string
  onThreadSelect: (agentId: string, threadId: string) => void
  onCreateThread: () => void
  onDeleteThread: (threadId: string) => void
  onRenameThread: (threadId: string, title: string) => void
}

export function AgentSidebar({
  mainAgentId,
  threads,
  activeThreadId,
  onThreadSelect,
  onCreateThread,
  onDeleteThread,
  onRenameThread,
}: AgentSidebarProps) {
  const [expandedAgents, setExpandedAgents] = useState<Set<string>>(
    new Set([mainAgentId])
  )
  const [editingThreadId, setEditingThreadId] = useState<string | null>(null)
  const [editingTitle, setEditingTitle] = useState("")
  const inputRef = useRef<HTMLInputElement>(null)

  const toggleAgent = (agentId: string) => {
    setExpandedAgents((prev) => {
      const next = new Set(prev)
      if (next.has(agentId)) {
        next.delete(agentId)
      } else {
        next.add(agentId)
      }
      return next
    })
  }

  const handleDelete = async (e: React.MouseEvent, threadId: string) => {
    e.stopPropagation()
    // Don't rely on the global `window.confirm` — Tauri v2 plugin-dialog
    // overrides it with an async Promise, which makes `if (confirm(...))`
    // always truthy (Promise is a truthy object) and leaks the unhandled
    // promise rejection path to the global error handler.
    onDeleteThread(threadId)
  }

  const startEditing = (e: React.MouseEvent, thread: Thread) => {
    e.stopPropagation()
    setEditingThreadId(thread.id)
    setEditingTitle(thread.title)
    // Focus input on next tick after render
    setTimeout(() => inputRef.current?.select(), 0)
  }

  const commitRename = () => {
    if (editingThreadId && editingTitle.trim()) {
      onRenameThread(editingThreadId, editingTitle.trim())
    }
    setEditingThreadId(null)
  }

  const cancelRename = () => {
    setEditingThreadId(null)
  }

  return (
    <div className="h-full w-64 bg-gray-50 border-r border-gray-200 flex flex-col">
      <div className="p-4 border-b border-gray-200">
        <div className="flex items-center gap-2 mb-3">
          <div className="w-8 h-8 bg-gradient-to-br from-blue-500 to-cyan-600 rounded-lg flex items-center justify-center">
            <span className="text-white text-sm font-bold">MA</span>
          </div>
          <div>
            <h2 className="text-sm font-bold text-gray-900">MyAgent</h2>
            <p className="text-xs text-gray-500">IT Governed</p>
          </div>
        </div>
        <input
          type="text"
          placeholder="Search..."
          className="w-full px-3 py-1.5 text-sm border border-gray-300 rounded-md focus:outline-none focus:ring-1 focus:ring-blue-500"
        />
      </div>


      <div className="flex-1 overflow-y-auto">
        <div className="px-4 py-2">
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center gap-2 text-xs font-medium text-gray-600">
              <span>CONVERSATIONS</span>
            </div>
          </div>

          <div className="space-y-1">
            {/* Main agent — owns real threads */}
            <div>
              <div
                className="flex items-center gap-2 py-1.5 px-2 rounded hover:bg-gray-200 cursor-pointer group transition-colors"
                onClick={() => toggleAgent(mainAgentId)}
              >
                {expandedAgents.has(mainAgentId) ? (
                  <ChevronDown className="w-3 h-3 text-gray-500" />
                ) : (
                  <ChevronRight className="w-3 h-3 text-gray-500" />
                )}
                <span className="text-lg">💬</span>
                <span className="text-sm font-medium text-gray-900 flex-1">
                  MyAgent
                </span>
                <button
                  className="opacity-0 group-hover:opacity-100 p-1 hover:bg-gray-300 rounded transition-opacity"
                  onClick={(e) => {
                    e.stopPropagation()
                    onCreateThread()
                  }}
                  title="New thread"
                >
                  <Plus className="w-3 h-3" />
                </button>
              </div>

              {expandedAgents.has(mainAgentId) && (
                <div className="ml-6 mt-1 space-y-0.5">
                  {threads.length === 0 ? (
                    <div className="py-2 px-3 text-xs text-gray-400 italic">
                      No threads
                    </div>
                  ) : (
                    threads.map((thread) => (
                      <div
                        key={thread.id}
                        className={`flex items-center gap-2 py-2 px-3 rounded cursor-pointer transition-colors group ${
                          activeThreadId === thread.id
                            ? "bg-blue-100 text-blue-900"
                            : "hover:bg-gray-200 text-gray-700"
                        }`}
                        onClick={() => {
                          if (editingThreadId !== thread.id) {
                            onThreadSelect(mainAgentId, thread.id)
                          }
                        }}
                      >
                        <MessageSquare className="w-3 h-3 flex-shrink-0" />
                        <div className="flex-1 min-w-0">
                          {editingThreadId === thread.id ? (
                            <input
                              ref={inputRef}
                              className="w-full text-xs font-medium bg-white border border-blue-400 rounded px-1 py-0.5 outline-none"
                              value={editingTitle}
                              onChange={(e) => setEditingTitle(e.target.value)}
                              onBlur={commitRename}
                              onKeyDown={(e) => {
                                if (e.key === "Enter") {
                                  e.preventDefault()
                                  commitRename()
                                } else if (e.key === "Escape") {
                                  cancelRename()
                                }
                              }}
                              onClick={(e) => e.stopPropagation()}
                            />
                          ) : (
                            <div className="text-xs font-medium truncate">
                              {thread.title}
                            </div>
                          )}
                        </div>
                        {editingThreadId !== thread.id && (
                          <>
                            <button
                              className="opacity-0 group-hover:opacity-100 p-1 hover:bg-gray-300 rounded transition-opacity"
                              onClick={(e) => startEditing(e, thread)}
                              title="Rename thread"
                            >
                              <Pencil className="w-3 h-3 text-gray-500" />
                            </button>
                            <button
                              className="opacity-0 group-hover:opacity-100 p-1 hover:bg-red-100 rounded transition-opacity"
                              onClick={(e) => handleDelete(e, thread.id)}
                              title="Delete thread"
                            >
                              <X className="w-3 h-3 text-red-500" />
                            </button>
                          </>
                        )}
                      </div>
                    ))
                  )}
                </div>
              )}
            </div>

          </div>
        </div>
      </div>
    </div>
  )
}
