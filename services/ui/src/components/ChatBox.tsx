import { useEffect, useRef } from "react"
import { Message } from "../store/chatStore"
import { Prism as SyntaxHighlighter } from "react-syntax-highlighter"
import { vscDarkPlus } from "react-syntax-highlighter/dist/esm/styles/prism"
import { Square } from "lucide-react"

interface ChatBoxProps {
  messages: Message[]
  input: string
  onInputChange: (value: string) => void
  onSend: () => void
  onStop?: () => void
  isLoading: boolean
}

export function ChatBox({ messages, input, onInputChange, onSend, onStop, isLoading }: ChatBoxProps) {
  const messagesEndRef = useRef<HTMLDivElement>(null)

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" })
  }

  useEffect(() => {
    scrollToBottom()
  }, [messages])

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault()
      onSend()
    }
  }

  const parseMessageContent = (content: string) => {
    const parts: JSX.Element[] = []
    const codeBlockRegex = /```(\w+)?\n([\s\S]*?)```/g
    let lastIndex = 0
    let match

    while ((match = codeBlockRegex.exec(content)) !== null) {
      if (match.index > lastIndex) {
        const textBefore = content.substring(lastIndex, match.index)
        parts.push(
          <div key={`text-${lastIndex}`} className="whitespace-pre-wrap">
            {textBefore.split("\n").map((line, i) => (
              <p key={i} className="my-1">{line || " "}</p>
            ))}
          </div>
        )
      }

      const language = match[1] || "text"
      const code = match[2].trim()
      parts.push(
        <div key={`code-${match.index}`} className="my-4 rounded-lg overflow-hidden">
          <div className="flex items-center justify-between bg-gray-800 px-4 py-2">
            <span className="text-xs font-mono text-gray-300">{language}</span>
            <button
              onClick={() => navigator.clipboard.writeText(code)}
              className="text-xs text-gray-400 hover:text-white transition-colors px-2 py-1 rounded hover:bg-gray-700"
            >
              Copy
            </button>
          </div>
          <SyntaxHighlighter
            language={language}
            style={vscDarkPlus}
            customStyle={{ margin: 0, borderRadius: 0, fontSize: "0.875rem", padding: "1rem" }}
          >
            {code}
          </SyntaxHighlighter>
        </div>
      )

      lastIndex = match.index + match[0].length
    }

    if (lastIndex < content.length) {
      const textAfter = content.substring(lastIndex)
      parts.push(
        <div key={`text-${lastIndex}`} className="whitespace-pre-wrap">
          {textAfter.split("\n").map((line, i) => (
            <p key={i} className="my-1">{line || " "}</p>
          ))}
        </div>
      )
    }

    return parts.length > 0 ? parts : <div className="whitespace-pre-wrap">{content}</div>
  }

  return (
    <div className="flex flex-col h-full bg-white rounded-xl shadow-lg border border-gray-200 overflow-hidden">
      <div className="flex-1 overflow-y-auto p-6 space-y-4">
        {messages.length === 0 && (
          <div className="flex-1 flex items-center justify-center h-full">
            <div className="text-center">
              <div className="w-16 h-16 bg-gradient-to-br from-blue-500 to-cyan-600 rounded-2xl flex items-center justify-center mx-auto mb-4">
                <span className="text-white text-2xl font-bold">MA</span>
              </div>
              <h2 className="text-xl font-semibold text-gray-900 mb-2">MyAgent</h2>
              <p className="text-gray-500 text-sm max-w-md">
                Ask me anything. I have access to Jira, Confluence, Outlook, and 5 LLM models with semantic routing.
              </p>
            </div>
          </div>
        )}

        {messages.map((message) => (
          <div
            key={message.id}
            className={`flex ${message.role === "user" ? "justify-end" : "justify-start"}`}
          >
            <div
              className={`max-w-[80%] rounded-2xl px-4 py-3 ${
                message.role === "user"
                  ? "bg-gradient-to-br from-blue-500 to-blue-600 text-white"
                  : "bg-gray-100 text-gray-900"
              }`}
            >
              {message.role === "assistant" ? (
                <div className="text-sm">{parseMessageContent(message.content)}</div>
              ) : (
                <p className="text-sm whitespace-pre-wrap">{message.content}</p>
              )}
              <div className={`text-xs mt-1 ${message.role === "user" ? "text-blue-100" : "text-gray-500"}`}>
                {message.timestamp.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
              </div>
            </div>
          </div>
        ))}

        {isLoading && (
          <div className="flex justify-start">
            <div className="bg-gray-100 rounded-2xl px-4 py-3">
              <div className="flex gap-1">
                <div className="w-2 h-2 bg-gray-400 rounded-full animate-bounce" style={{ animationDelay: "0ms" }} />
                <div className="w-2 h-2 bg-gray-400 rounded-full animate-bounce" style={{ animationDelay: "150ms" }} />
                <div className="w-2 h-2 bg-gray-400 rounded-full animate-bounce" style={{ animationDelay: "300ms" }} />
              </div>
            </div>
          </div>
        )}

        <div ref={messagesEndRef} />
      </div>

      <div className="border-t border-gray-200 p-4 bg-gray-50">
        <div className="flex gap-3">
          <textarea
            value={input}
            onChange={(e) => onInputChange(e.target.value)}
            onKeyPress={handleKeyPress}
            placeholder="Ask MyAgent... (Shift+Enter for new line)"
            className="flex-1 resize-none rounded-lg border border-gray-300 px-4 py-3 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent text-sm"
            rows={1}
            disabled={isLoading}
          />
          {isLoading && onStop ? (
            <button
              onClick={onStop}
              className="px-4 py-3 rounded-lg font-medium text-sm bg-red-500 text-white hover:bg-red-600 shadow-md transition-all"
              title="Stop generating"
            >
              <Square className="w-4 h-4" />
            </button>
          ) : (
            <button
              onClick={onSend}
              disabled={!input.trim() || isLoading}
              className={`px-6 py-3 rounded-lg font-medium text-sm transition-all ${
                !input.trim() || isLoading
                  ? "bg-gray-300 text-gray-500 cursor-not-allowed"
                  : "bg-gradient-to-r from-blue-500 to-cyan-600 text-white hover:from-blue-600 hover:to-cyan-700 shadow-md hover:shadow-lg"
              }`}
            >
              Send
            </button>
          )}
        </div>
        <p className="text-xs text-gray-400 mt-2">
          Powered by MyAgent IT Governed Mode | Semantic Router + LiteLLM + Guardrails
        </p>
      </div>
    </div>
  )
}
