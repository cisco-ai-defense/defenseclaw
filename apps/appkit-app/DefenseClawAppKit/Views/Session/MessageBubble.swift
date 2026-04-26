import SwiftUI
import DefenseClawKit

struct MessageBubble: View {
    let message: ChatMessage
    let viewModel: SessionViewModel

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            if message.role == .user {
                Spacer(minLength: 60)
            } else {
                // Assistant avatar
                Image(systemName: "shield.checkered")
                    .font(.system(size: 14))
                    .foregroundStyle(.white)
                    .frame(width: 28, height: 28)
                    .background(
                        LinearGradient(
                            colors: [Color.blue, Color.indigo],
                            startPoint: .topLeading,
                            endPoint: .bottomTrailing
                        )
                    )
                    .clipShape(Circle())
            }

            VStack(alignment: message.role == .user ? .trailing : .leading, spacing: 4) {
                // Role label + timestamp
                HStack(spacing: 6) {
                    Text(message.role == .user ? "You" : "DefenseClaw")
                        .font(.caption)
                        .fontWeight(.medium)
                        .foregroundStyle(.secondary)
                    Text(message.timestamp, style: .time)
                        .font(.caption2)
                        .foregroundStyle(.tertiary)
                }

                // Content blocks
                VStack(alignment: .leading, spacing: 8) {
                    ForEach(message.blocks) { block in
                        contentView(for: block)
                    }
                }
                .padding(12)
                .background(bubbleBackground)
                .clipShape(RoundedRectangle(cornerRadius: 12))
                .overlay(
                    RoundedRectangle(cornerRadius: 12)
                        .stroke(bubbleBorder, lineWidth: 0.5)
                )

                // Streaming indicator
                if message.isStreaming {
                    HStack(spacing: 4) {
                        ProgressView()
                            .controlSize(.mini)
                        Text("Responding...")
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                    }
                }
            }

            if message.role == .user {
                // User avatar
                Image(systemName: "person.fill")
                    .font(.system(size: 13))
                    .foregroundStyle(.white)
                    .frame(width: 28, height: 28)
                    .background(Color.accentColor)
                    .clipShape(Circle())
            } else {
                Spacer(minLength: 60)
            }
        }
    }

    private var bubbleBackground: some View {
        Group {
            if message.role == .user {
                Color.accentColor.opacity(0.08)
            } else {
                Color(nsColor: .textBackgroundColor)
            }
        }
    }

    private var bubbleBorder: Color {
        if message.role == .user {
            return Color.accentColor.opacity(0.15)
        } else {
            return Color(nsColor: .separatorColor).opacity(0.5)
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
