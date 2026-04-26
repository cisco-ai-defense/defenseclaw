import SwiftUI
import DefenseClawKit

struct ApprovalCard: View {
    let requestId: String
    let command: String
    let cwd: String
    let isDangerous: Bool
    let decision: ApprovalDecision?
    let viewModel: SessionViewModel

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Image(systemName: isDangerous ? "exclamationmark.triangle.fill" : "questionmark.circle")
                    .foregroundStyle(isDangerous ? .red : .orange)
                Text(isDangerous ? "Dangerous Command" : "Approval Required")
                    .font(.caption)
                    .fontWeight(.semibold)
                Spacer()
            }

            Text(command)
                .font(.caption)
                .fontWeight(.medium)
                .padding(6)
                .background(Color.black.opacity(0.05))
                .cornerRadius(4)

            if !cwd.isEmpty {
                Text("Working directory: \(cwd)")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }

            if let decision = decision {
                HStack {
                    Image(systemName: decision == .approved || decision == .autoApproved ? "checkmark.circle.fill" : "xmark.circle.fill")
                        .foregroundStyle(decision == .approved || decision == .autoApproved ? .green : .red)
                    Text(decision == .autoApproved ? "Auto-approved" : (decision == .approved ? "Approved" : "Denied"))
                        .font(.caption)
                }
            } else {
                HStack(spacing: 12) {
                    Spacer()

                    Button {
                        viewModel.denyExec(requestId: requestId)
                    } label: {
                        Label("Deny", systemImage: "xmark")
                            .font(.caption)
                    }
                    .buttonStyle(.bordered)
                    .tint(.red)

                    Button {
                        viewModel.approveExec(requestId: requestId)
                    } label: {
                        Label("Approve", systemImage: "checkmark")
                            .font(.caption)
                    }
                    .buttonStyle(.bordered)
                    .tint(.green)
                }
            }
        }
        .padding(12)
        .background(isDangerous ? Color.red.opacity(0.05) : Color.orange.opacity(0.05))
        .cornerRadius(8)
        .overlay(
            RoundedRectangle(cornerRadius: 8)
                .stroke(isDangerous ? Color.red.opacity(0.3) : Color.orange.opacity(0.3), lineWidth: 1)
        )
    }
}
