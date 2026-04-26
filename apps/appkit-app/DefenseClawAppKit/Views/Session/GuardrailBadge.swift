import SwiftUI
import DefenseClawKit

struct GuardrailBadge: View {
    let severity: String
    let action: String
    let reason: String

    var body: some View {
        HStack(spacing: 6) {
            Image(systemName: "shield.lefthalf.filled")
                .foregroundStyle(severityColor)

            VStack(alignment: .leading, spacing: 2) {
                HStack {
                    Text(action.uppercased())
                        .font(.caption)
                        .fontWeight(.bold)
                    Text("·")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Text(severity.uppercased())
                        .font(.caption)
                        .fontWeight(.medium)
                }

                Text(reason)
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 6)
        .background(severityColor.opacity(0.1))
        .cornerRadius(6)
        .overlay(
            RoundedRectangle(cornerRadius: 6)
                .stroke(severityColor.opacity(0.3), lineWidth: 1)
        )
    }

    private var severityColor: Color {
        switch severity.lowercased() {
        case "critical":
            return .red
        case "high":
            return .orange
        case "medium":
            return .yellow
        case "low":
            return .blue
        default:
            return .gray
        }
    }
}
