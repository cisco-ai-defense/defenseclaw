import type { ChatMessage, ContentBlock, ApprovalDecision } from '@/types/chat';
import { isDangerousCommand } from '@/types/chat';

const GATEWAY_WS_URL = 'ws://127.0.0.1:18789';

export interface SessionMessage {
  type: 'chat' | 'tool_call' | 'approval_request' | 'status';
  payload: unknown;
}

export interface AgentSessionOptions {
  onMessage?: (message: ChatMessage) => void;
  onToolCall?: (toolCall: ContentBlock & { type: 'tool_call' }) => void;
  onApprovalRequest?: (request: ContentBlock & { type: 'approval_request' }) => void;
  onError?: (error: Error) => void;
  onClose?: () => void;
}

export class AgentSession {
  private ws: WebSocket | null = null;
  private url: string;
  private options: AgentSessionOptions;
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 5;
  private reconnectDelay = 1000;

  constructor(url: string = GATEWAY_WS_URL, options: AgentSessionOptions = {}) {
    this.url = url;
    this.options = options;
  }

  connect(): void {
    if (this.ws?.readyState === WebSocket.OPEN) {
      console.warn('WebSocket already connected');
      return;
    }

    try {
      this.ws = new WebSocket(this.url);

      this.ws.onopen = () => {
        console.log('WebSocket connected');
        this.reconnectAttempts = 0;
      };

      this.ws.onmessage = (event) => {
        try {
          const message = JSON.parse(event.data) as SessionMessage;
          this.handleMessage(message);
        } catch (error) {
          console.error('Failed to parse WebSocket message:', error);
          this.options.onError?.(error as Error);
        }
      };

      this.ws.onerror = (error) => {
        console.error('WebSocket error:', error);
        this.options.onError?.(new Error('WebSocket connection error'));
      };

      this.ws.onclose = () => {
        console.log('WebSocket closed');
        this.options.onClose?.();
        this.attemptReconnect();
      };
    } catch (error) {
      console.error('Failed to create WebSocket:', error);
      this.options.onError?.(error as Error);
    }
  }

  private attemptReconnect(): void {
    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      console.error('Max reconnection attempts reached');
      return;
    }

    this.reconnectAttempts++;
    const delay = this.reconnectDelay * Math.pow(2, this.reconnectAttempts - 1);

    console.log(`Attempting to reconnect in ${delay}ms (attempt ${this.reconnectAttempts})`);

    setTimeout(() => {
      this.connect();
    }, delay);
  }

  private handleMessage(message: SessionMessage): void {
    switch (message.type) {
      case 'chat':
        this.handleChatMessage(message.payload as ChatMessage);
        break;

      case 'tool_call':
        this.handleToolCall(message.payload as ContentBlock & { type: 'tool_call' });
        break;

      case 'approval_request':
        this.handleApprovalRequest(message.payload as ContentBlock & { type: 'approval_request' });
        break;

      case 'status':
        // Handle status updates (e.g., "thinking", "typing")
        console.log('Status update:', message.payload);
        break;

      default:
        console.warn('Unknown message type:', message);
    }
  }

  private handleChatMessage(message: ChatMessage): void {
    this.options.onMessage?.(message);
  }

  private handleToolCall(toolCall: ContentBlock & { type: 'tool_call' }): void {
    this.options.onToolCall?.(toolCall);
  }

  private handleApprovalRequest(request: ContentBlock & { type: 'approval_request' }): void {
    // Enhance approval request with dangerous command detection
    const isDangerous = isDangerousCommand(request.command);
    const enhancedRequest = {
      ...request,
      isDangerous,
    };
    this.options.onApprovalRequest?.(enhancedRequest);
  }

  sendMessage(text: string): void {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
      throw new Error('WebSocket is not connected');
    }

    const message: SessionMessage = {
      type: 'chat',
      payload: {
        role: 'user',
        content: [{ type: 'text', id: crypto.randomUUID(), text }],
        timestamp: new Date().toISOString(),
      },
    };

    this.ws.send(JSON.stringify(message));
  }

  approveCommand(requestId: string, decision: ApprovalDecision): void {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
      throw new Error('WebSocket is not connected');
    }

    const message: SessionMessage = {
      type: 'approval_request',
      payload: {
        requestId,
        decision,
      },
    };

    this.ws.send(JSON.stringify(message));
  }

  disconnect(): void {
    if (this.ws) {
      this.reconnectAttempts = this.maxReconnectAttempts; // Prevent reconnection
      this.ws.close();
      this.ws = null;
    }
  }

  isConnected(): boolean {
    return this.ws?.readyState === WebSocket.OPEN;
  }
}
