import SwiftUI
import DefenseClawKit

struct MessageBubble: View {
    let message: ChatMessage
    let viewModel: SessionViewModel

    var body: some View {
        VStack(alignment: message.role == .user ? .trailing : .leading, spacing: 8) {
            HStack {
                if message.role == .user {
                    Spacer()
                }

                VStack(alignment: .leading, spacing: 8) {
                    ForEach(message.blocks) { block in
                        contentView(for: block)
                    }
                }
                .padding(12)
                .background(message.role == .user ? Color.blue.opacity(0.1) : Color.gray.opacity(0.1))
                .cornerRadius(12)

                if message.role == .assistant {
                    Spacer()
                }
            }
        }
    }

    @ViewBuilder
    private func contentView(for block: ContentBlock) -> some View {
        switch block {
        case .text(_, let text):
            MarkdownRenderer(text: text)

        case .thinking(_, let text, _):
            ThinkingView(thought: text)

        case .toolCall(_, let tool, let args, let status, let output, _):
            ToolCallCard(tool: tool, args: args, status: status, output: output, viewModel: viewModel)

        case .approvalRequest(let id, let command, let cwd, let isDangerous, let decision):
            ApprovalCard(requestId: id, command: command, cwd: cwd, isDangerous: isDangerous, decision: decision, viewModel: viewModel)

        case .guardrailBadge(_, let severity, let action, let reason):
            GuardrailBadge(severity: severity, action: action, reason: reason)
        }
    }
}
