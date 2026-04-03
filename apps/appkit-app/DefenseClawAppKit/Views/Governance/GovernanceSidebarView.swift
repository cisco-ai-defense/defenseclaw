import SwiftUI
import DefenseClawKit

struct GovernanceSidebarView: View {
    @Bindable var viewModel: SessionViewModel

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text("Governance")
                    .font(.headline)
                Spacer()
                Button {
                    Task {
                        await viewModel.refreshGovernance()
                    }
                } label: {
                    Image(systemName: "arrow.clockwise")
                }
                .buttonStyle(.borderless)
            }
            .padding()

            Divider()

            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    alertsSection
                    skillsSection
                    mcpSection
                }
                .padding()
            }
        }
        .background(Color(nsColor: .controlBackgroundColor))
    }

    private var alertsSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Alerts")
                .font(.subheadline)
                .fontWeight(.semibold)

            if viewModel.governanceAlerts.isEmpty {
                Text("No alerts")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            } else {
                ForEach(viewModel.governanceAlerts) { alert in
                    AlertRow(alert: alert)
                }
            }
        }
    }

    private var skillsSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Skills")
                .font(.subheadline)
                .fontWeight(.semibold)

            if viewModel.skills.isEmpty {
                Text("No skills")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            } else {
                ForEach(viewModel.skills) { skill in
                    SkillRow(skill: skill)
                }
            }
        }
    }

    private var mcpSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("MCP Servers")
                .font(.subheadline)
                .fontWeight(.semibold)

            if viewModel.mcpServers.isEmpty {
                Text("No MCP servers")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            } else {
                ForEach(viewModel.mcpServers) { server in
                    MCPRow(server: server)
                }
            }
        }
    }
}
