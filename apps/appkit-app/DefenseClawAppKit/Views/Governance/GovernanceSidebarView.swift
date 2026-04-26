import SwiftUI
import DefenseClawKit

struct GovernanceSidebarView: View {
    @Bindable var viewModel: SessionViewModel

    var body: some View {
        VStack(spacing: 0) {
            // Header
            HStack {
                Image(systemName: "shield.checkered")
                    .foregroundStyle(.blue)
                Text("Governance")
                    .font(.headline)
                Spacer()
                Button {
                    Task {
                        await viewModel.refreshGovernance()
                    }
                } label: {
                    Image(systemName: "arrow.clockwise")
                        .font(.caption)
                }
                .buttonStyle(.borderless)
                .help("Refresh governance data")
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 12)

            Divider()

            ScrollView {
                VStack(spacing: 12) {
                    alertsCard
                    skillsCard
                    mcpCard
                }
                .padding(12)
            }
        }
        .background(Color(nsColor: .windowBackgroundColor))
    }

    // MARK: - Alerts Card

    private var alertsCard: some View {
        SidebarCard(title: "Alerts", icon: "bell.badge", iconColor: .orange) {
            if viewModel.governanceAlerts.isEmpty {
                HStack(spacing: 6) {
                    Image(systemName: "checkmark.shield.fill")
                        .foregroundStyle(.green)
                        .font(.caption)
                    Text("No active alerts")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            } else {
                ForEach(viewModel.governanceAlerts) { alert in
                    AlertRow(alert: alert)
                }
            }
        }
    }

    // MARK: - Skills Card

    private var skillsCard: some View {
        SidebarCard(title: "Skills", icon: "wand.and.stars", iconColor: .purple, badge: "\(viewModel.skills.count)") {
            if viewModel.skills.isEmpty {
                Text("No skills discovered")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            } else {
                ForEach(viewModel.skills) { skill in
                    SkillRow(skill: skill)
                }
            }
        }
    }

    // MARK: - MCP Card

    private var mcpCard: some View {
        SidebarCard(title: "MCP Servers", icon: "server.rack", iconColor: .teal, badge: "\(viewModel.mcpServers.count)") {
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

// MARK: - Sidebar Card Container

struct SidebarCard<Content: View>: View {
    let title: String
    let icon: String
    let iconColor: Color
    var badge: String? = nil
    @ViewBuilder let content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 6) {
                Image(systemName: icon)
                    .font(.caption)
                    .foregroundStyle(iconColor)
                Text(title)
                    .font(.subheadline)
                    .fontWeight(.semibold)
                if let badge, !badge.isEmpty, badge != "0" {
                    Text(badge)
                        .font(.caption2)
                        .fontWeight(.medium)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 1)
                        .background(iconColor.opacity(0.15))
                        .foregroundStyle(iconColor)
                        .clipShape(Capsule())
                }
                Spacer()
            }

            content
        }
        .padding(12)
        .background(Color(nsColor: .controlBackgroundColor))
        .clipShape(RoundedRectangle(cornerRadius: 10))
        .overlay(
            RoundedRectangle(cornerRadius: 10)
                .stroke(Color(nsColor: .separatorColor).opacity(0.5), lineWidth: 0.5)
        )
    }
}
