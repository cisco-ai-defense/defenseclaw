import SwiftUI
import DefenseClawKit

struct MCPRow: View {
    let server: MCPServer

    var body: some View {
        HStack(spacing: 8) {
            Circle()
                .fill(server.isRunning ? Color.green : Color.gray)
                .frame(width: 8, height: 8)

            Text(server.name)
                .font(.caption)
                .lineLimit(1)

            Spacer()

            if server.blocked {
                Text("Blocked")
                    .font(.caption2)
                    .foregroundStyle(.red)
            } else {
                Text(server.isRunning ? "Running" : "Stopped")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
        }
        .padding(8)
        .background(Color.gray.opacity(0.05))
        .cornerRadius(6)
    }
}
