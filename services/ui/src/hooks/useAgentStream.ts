import { useRef, useCallback } from "react"
import { useChatStore } from "../store/chatStore"
import { toast } from "sonner"

const LITELLM_URL = import.meta.env.VITE_LITELLM_URL || "http://127.0.0.1:4001"
const LITELLM_KEY = import.meta.env.VITE_LITELLM_KEY || ""

export function useAgentStream() {
  const abortRef = useRef<AbortController | null>(null)
  const { addMessage, updateMessage, setLoading } = useChatStore()

  const stopStream = useCallback(() => {
    if (abortRef.current) {
      abortRef.current.abort()
      abortRef.current = null
      setLoading(false)
    }
  }, [setLoading])

  const processAgentStream = useCallback(
    async (_userMessage: string, _userMessageId: string, threadId: string): Promise<void> => {
      if (!threadId) {
        toast.error("No active thread")
        return
      }

      setLoading(true)
      abortRef.current = new AbortController()

      const assistantMessageId = crypto.randomUUID()
      addMessage(threadId, {
        id: assistantMessageId,
        role: "assistant",
        content: "",
        timestamp: new Date(),
      })

      try {
        const history = useChatStore
          .getState()
          .messages.filter((m) => m.id !== assistantMessageId)
          .map((m) => ({ role: m.role, content: m.content }))

        const headers: Record<string, string> = { "Content-Type": "application/json" }
        if (LITELLM_KEY) headers["Authorization"] = `Bearer ${LITELLM_KEY}`

        const response = await fetch(`${LITELLM_URL}/v1/responses`, {
          method: "POST",
          headers,
          body: JSON.stringify({
            model: "default",
            input: history,
            stream: true,
          }),
          signal: abortRef.current.signal,
        })

        if (!response.ok) {
          const err = await response.text()
          throw new Error(`API ${response.status}: ${err.slice(0, 200)}`)
        }

        const reader = response.body?.getReader()
        if (!reader) throw new Error("No response stream")

        const decoder = new TextDecoder()
        let buffer = ""
        let fullText = ""

        while (true) {
          const { done, value } = await reader.read()
          if (done) break

          buffer += decoder.decode(value, { stream: true })
          const lines = buffer.split("\n")
          buffer = lines.pop() || ""

          for (const line of lines) {
            if (!line.startsWith("data: ")) continue
            const data = line.slice(6).trim()
            if (data === "[DONE]") continue

            try {
              const event = JSON.parse(data)

              if (event.type === "response.output_text.delta" && event.delta) {
                fullText += event.delta
                updateMessage(threadId, assistantMessageId, { content: fullText })
              }
            } catch {
              // Skip malformed SSE lines
            }
          }
        }

        if (!fullText) {
          updateMessage(threadId, assistantMessageId, { content: "(No response)" })
        }
      } catch (err: unknown) {
        if (err instanceof DOMException && err.name === "AbortError") return
        const msg = err instanceof Error ? err.message : "Unknown error"
        toast.error(`Failed: ${msg}`)
        updateMessage(threadId, assistantMessageId, { content: `Error: ${msg}` })
      } finally {
        setLoading(false)
        abortRef.current = null
      }
    },
    [addMessage, updateMessage, setLoading]
  )

  return { processAgentStream, stopStream }
}
