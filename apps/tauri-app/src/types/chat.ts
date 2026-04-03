// Message role in chat
export type MessageRole = 'user' | 'assistant' | 'system';

// Tool call execution status
export type ToolCallStatus = 'pending' | 'running' | 'success' | 'error' | 'blocked';

// Approval decision for dangerous commands
export type ApprovalDecision = 'approved' | 'rejected' | 'pending';

// Content block types (union type for different content)
export type ContentBlock =
  | { type: 'text'; id: string; text: string }
  | { type: 'thinking'; id: string; text: string; durationMs?: number }
  | {
      type: 'tool_call';
      id: string;
      tool: string;
      args: string;
      status: ToolCallStatus;
      output?: string;
      elapsedMs?: number
    }
  | {
      type: 'approval_request';
      id: string;
      command: string;
      cwd: string;
      isDangerous: boolean;
      decision?: ApprovalDecision
    }
  | {
      type: 'guardrail_badge';
      id: string;
      severity: string;
      action: string;
      reason: string
    };

// Chat message
export interface ChatMessage {
  id: string;
  role: MessageRole;
  content: ContentBlock[];
  timestamp: string; // ISO timestamp
}

// Dangerous command patterns for client-side detection
export const DANGEROUS_PATTERNS = [
  'curl',
  'wget',
  'nc',
  'ncat',
  'netcat',
  '/dev/tcp',
  'base64 -d',
  'base64 --decode',
  'eval',
  'bash -c',
  'sh -c',
  'python -c',
  'perl -e',
  'ruby -e',
  'rm -rf /',
  'dd if=',
  'mkfs',
  'chmod 777',
  '> /etc/',
  '>> /etc/',
  'passwd',
  'shadow',
  'sudoers',
] as const;

// Check if a command contains dangerous patterns
export function isDangerousCommand(command: string): boolean {
  const lower = command.toLowerCase();
  return DANGEROUS_PATTERNS.some(pattern => lower.includes(pattern));
}
