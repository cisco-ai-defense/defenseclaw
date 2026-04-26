import SwiftUI
import DefenseClawKit

struct ToolCallCard: View {
    let tool: String
    let args: String
    let status: ToolCallStatus
    let output: String?
    let viewModel: SessionViewModel

    @State private var isOutputExpanded = false

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            // Header: icon + tool name + status badge
            HStack(spacing: 8) {
                Image(systemName: toolIcon)
                    .font(.system(size: 12, weight: .medium))
                    .foregroundStyle(.white)
                    .frame(width: 22, height: 22)
                    .background(statusColor.opacity(0.9))
                    .clipShape(RoundedRectangle(cornerRadius: 5))

                Text(tool)
                    .font(.system(.body, design: .monospaced, weight: .medium))
                    .lineLimit(1)

                Spacer()

                statusBadge
            }

            // Arguments
            if !args.isEmpty {
                Text(args)
                    .font(.system(.caption, design: .monospaced))
                    .foregroundStyle(.secondary)
                    .lineLimit(3)
                    .padding(8)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(Color(nsColor: .textBackgroundColor).opacity(0.5))
                    .clipShape(RoundedRectangle(cornerRadius: 6))
            }

            // Collapsible output
            if let output, !output.isEmpty {
                Button {
                    withAnimation(.easeInOut(duration: 0.2)) {
                        isOutputExpanded.toggle()
                    }
                } label: {
                    HStack(spacing: 4) {
                        Image(systemName: isOutputExpanded ? "chevron.down" : "chevron.right")
                            .font(.caption2)
                        Text("Output")
                            .font(.caption)
                        Text("(\(output.count) chars)")
                            .font(.caption2)
                            .foregroundStyle(.tertiary)
                        Spacer()
                    }
                    .foregroundStyle(.secondary)
                }
                .buttonStyle(.plain)

                if isOutputExpanded {
                    ScrollView {
                        Text(output)
                            .font(.system(.caption, design: .monospaced))
                            .textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(8)
                    }
                    .frame(maxHeight: 200)
                    .background(Color(nsColor: .textBackgroundColor))
                    .clipShape(RoundedRectangle(cornerRadius: 6))
                }
            }

            // Elapsed time
            if status == .running {
                HStack(spacing: 4) {
                    ProgressView()
                        .controlSize(.mini)
                    Text("Running...")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
            }
        }
        .padding(12)
        .background(statusColor.opacity(0.04))
        .clipShape(RoundedRectangle(cornerRadius: 10))
        .overlay(
            RoundedRectangle(cornerRadius: 10)
                .stroke(statusColor.opacity(0.2), lineWidth: 1)
        )
    }

    private var toolIcon: String {
        switch status {
        case .completed: return "checkmark"
        case .failed: return "xmark"
        case .running: return "arrow.clockwise"
        case .pending: return "clock"
        case .warned: return "exclamationmark.triangle"
        case .blocked: return "hand.raised.fill"
        }
    }

    private var statusColor: Color {
        switch status {
        case .completed: return .green
        case .failed: return .red
        case .running: return .blue
        case .pending: return .orange
        case .warned: return .yellow
        case .blocked: return .red
        }
    }

    @ViewBuilder
    private var statusBadge: some View {
        let label: String = {
            switch status {
            case .completed: return "Done"
            case .failed: return "Failed"
            case .running: return "Running"
            case .pending: return "Pending"
            case .warned: return "Warning"
            case .blocked: return "Blocked"
            }
        }()

        Text(label)
            .font(.caption2)
            .fontWeight(.medium)
            .padding(.horizontal, 8)
            .padding(.vertical, 2)
            .background(statusColor.opacity(0.12))
            .foregroundStyle(statusColor)
            .clipShape(Capsule())
    }
}
