import { useState, useEffect, useCallback, useRef } from 'react';
import { AgentSession } from '@/services/agent-session';
import type { ChatMessage, ContentBlock, ApprovalDecision } from '@/types/chat';

export interface UseSessionResult {
  messages: ChatMessage[];
  isConnected: boolean;
  sendMessage: (text: string) => void;
  approveCommand: (requestId: string, decision: ApprovalDecision) => void;
  appendToolCall: (toolCall: ContentBlock & { type: 'tool_call' }) => void;
  updateToolResult: (toolCallId: string, output: string, status: 'success' | 'error') => void;
  appendApproval: (request: ContentBlock & { type: 'approval_request' }) => void;
}

export function useSession(): UseSessionResult {
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [isConnected, setIsConnected] = useState(false);
  const sessionRef = useRef<AgentSession | null>(null);

  useEffect(() => {
    const session = new AgentSession(undefined, {
      onMessage: (message) => {
        setMessages((prev) => [...prev, message]);
      },
      onToolCall: (toolCall) => {
        // Add tool call as a content block to the last assistant message
        setMessages((prev) => {
          if (prev.length === 0) return prev;

          const lastMessage = prev[prev.length - 1];
          if (lastMessage.role !== 'assistant') {
            // Create a new assistant message with the tool call
            return [
              ...prev,
              {
                id: crypto.randomUUID(),
                role: 'assistant' as const,
                content: [toolCall],
                timestamp: new Date().toISOString(),
              },
            ];
          }

          // Append to existing assistant message
          return [
            ...prev.slice(0, -1),
            {
              ...lastMessage,
              content: [...lastMessage.content, toolCall],
            },
          ];
        });
      },
      onApprovalRequest: (request) => {
        // Add approval request as a content block
        setMessages((prev) => {
          if (prev.length === 0) return prev;

          const lastMessage = prev[prev.length - 1];
          if (lastMessage.role !== 'assistant') {
            // Create a new assistant message with the approval request
            return [
              ...prev,
              {
                id: crypto.randomUUID(),
                role: 'assistant' as const,
                content: [request],
                timestamp: new Date().toISOString(),
              },
            ];
          }

          // Append to existing assistant message
          return [
            ...prev.slice(0, -1),
            {
              ...lastMessage,
              content: [...lastMessage.content, request],
            },
          ];
        });
      },
      onError: (error) => {
        console.error('Session error:', error);
        setIsConnected(false);
      },
      onClose: () => {
        setIsConnected(false);
      },
    });

    sessionRef.current = session;
    session.connect();
    setIsConnected(true);

    return () => {
      session.disconnect();
    };
  }, []);

  const sendMessage = useCallback((text: string) => {
    if (!sessionRef.current) return;

    // Add user message immediately
    const userMessage: ChatMessage = {
      id: crypto.randomUUID(),
      role: 'user',
      content: [{ type: 'text', id: crypto.randomUUID(), text }],
      timestamp: new Date().toISOString(),
    };
    setMessages((prev) => [...prev, userMessage]);

    // Send via WebSocket
    sessionRef.current.sendMessage(text);
  }, []);

  const approveCommand = useCallback((requestId: string, decision: ApprovalDecision) => {
    if (!sessionRef.current) return;
    sessionRef.current.approveCommand(requestId, decision);

    // Update the approval request in the message history
    setMessages((prev) => {
      return prev.map((message) => {
        if (message.role !== 'assistant') return message;

        return {
          ...message,
          content: message.content.map((block) => {
            if (block.type === 'approval_request' && block.id === requestId) {
              return { ...block, decision };
            }
            return block;
          }),
        };
      });
    });
  }, []);

  const appendToolCall = useCallback((toolCall: ContentBlock & { type: 'tool_call' }) => {
    setMessages((prev) => {
      if (prev.length === 0) return prev;

      const lastMessage = prev[prev.length - 1];
      if (lastMessage.role !== 'assistant') {
        return [
          ...prev,
          {
            id: crypto.randomUUID(),
            role: 'assistant' as const,
            content: [toolCall],
            timestamp: new Date().toISOString(),
          },
        ];
      }

      return [
        ...prev.slice(0, -1),
        {
          ...lastMessage,
          content: [...lastMessage.content, toolCall],
        },
      ];
    });
  }, []);

  const updateToolResult = useCallback(
    (toolCallId: string, output: string, status: 'success' | 'error') => {
      setMessages((prev) => {
        return prev.map((message) => {
          if (message.role !== 'assistant') return message;

          return {
            ...message,
            content: message.content.map((block) => {
              if (block.type === 'tool_call' && block.id === toolCallId) {
                return { ...block, output, status };
              }
              return block;
            }),
          };
        });
      });
    },
    []
  );

  const appendApproval = useCallback((request: ContentBlock & { type: 'approval_request' }) => {
    setMessages((prev) => {
      if (prev.length === 0) return prev;

      const lastMessage = prev[prev.length - 1];
      if (lastMessage.role !== 'assistant') {
        return [
          ...prev,
          {
            id: crypto.randomUUID(),
            role: 'assistant' as const,
            content: [request],
            timestamp: new Date().toISOString(),
          },
        ];
      }

      return [
        ...prev.slice(0, -1),
        {
          ...lastMessage,
          content: [...lastMessage.content, request],
        },
      ];
    });
  }, []);

  return {
    messages,
    isConnected,
    sendMessage,
    approveCommand,
    appendToolCall,
    updateToolResult,
    appendApproval,
  };
}
