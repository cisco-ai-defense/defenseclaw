import SwiftUI
import DefenseClawKit

struct ToolCallCard: View {
    let tool: String
    let args: String
    let status: ToolCallStatus
    let output: String?
    let viewModel: SessionViewModel

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Image(systemName: "wrench.and.screwdriver")
                    .foregroundStyle(.blue)
                Text(tool)
                    .font(.headline)
                Spacer()
                statusBadge
            }

            if !args.isEmpty {
                Text(args)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(3)
            }

            if let output = output {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Output:")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Text(output)
                        .font(.caption)
                        .padding(8)
                        .background(Color.gray.opacity(0.1))
                        .cornerRadius(4)
                }
            }
        }
        .padding()
        .background(Color.blue.opacity(0.05))
        .cornerRadius(8)
        .overlay(
            RoundedRectangle(cornerRadius: 8)
                .stroke(Color.blue.opacity(0.3), lineWidth: 1)
        )
    }

    @ViewBuilder
    private var statusBadge: some View {
        switch status {
        case .completed:
            Label("Completed", systemImage: "checkmark.circle.fill")
                .font(.caption)
                .foregroundStyle(.green)
        case .failed:
            Label("Failed", systemImage: "xmark.circle.fill")
                .font(.caption)
                .foregroundStyle(.red)
        case .running:
            Label("Running", systemImage: "arrow.clockwise")
                .font(.caption)
                .foregroundStyle(.blue)
        case .pending:
            Label("Pending", systemImage: "clock")
                .font(.caption)
                .foregroundStyle(.orange)
        case .warned:
            Label("Warning", systemImage: "exclamationmark.triangle")
                .font(.caption)
                .foregroundStyle(.yellow)
        case .blocked:
            Label("Blocked", systemImage: "hand.raised")
                .font(.caption)
                .foregroundStyle(.red)
        }
    }
}
