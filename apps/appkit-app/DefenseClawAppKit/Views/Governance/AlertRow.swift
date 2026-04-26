import SwiftUI
import DefenseClawKit

struct AlertRow: View {
    let alert: DefenseClawKit.Alert

    var body: some View {
        HStack(spacing: 8) {
            Circle()
                .fill(severityColor)
                .frame(width: 8, height: 8)

            VStack(alignment: .leading, spacing: 2) {
                Text(alert.message.isEmpty ? alert.details : alert.message)
                    .font(.caption)
                    .lineLimit(2)

                Text(alert.timestamp, style: .relative)
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }

            Spacer()
        }
        .padding(8)
        .background(severityColor.opacity(0.05))
        .cornerRadius(6)
    }

    private var severityColor: Color {
        switch alert.severity {
        case .critical:
            return .red
        case .high:
            return .orange
        case .medium:
            return .yellow
        case .low:
            return .blue
        case .info:
            return .green
        case .none:
            return .gray
        }
    }
}
