import SwiftUI

struct SettingsOverviewView: View {
    let openSetup: () -> Void
    let openConfig: () -> Void
    let openGateway: () -> Void
    let openGuardrails: () -> Void
    let openEnforcement: () -> Void
    let openScanners: () -> Void
    let openDiagnostics: () -> Void
    let openPolicy: () -> Void
    let openAlerts: () -> Void
    let openLogs: () -> Void

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 22) {
                header
                primaryFlows
                settingsByRole
                advancedAccess
            }
            .padding(24)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .background(Color(nsColor: .windowBackgroundColor))
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 7) {
            Text("Settings Overview")
                .font(.largeTitle.weight(.semibold))
            Text("Choose the workflow you are trying to complete. Most users should not start in raw YAML.")
                .font(.callout)
                .foregroundStyle(.secondary)
        }
    }

    private var primaryFlows: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Start Here")
                .font(.title3.weight(.semibold))

            LazyVGrid(columns: [GridItem(.adaptive(minimum: 260), spacing: 12)], spacing: 12) {
                SettingsFlowCard(
                    title: "Install or Repair Backend",
                    subtitle: "First launch, upgrades, missing helper, broken health checks.",
                    systemImage: "wrench.and.screwdriver",
                    tint: .blue,
                    actionTitle: "Open Setup",
                    action: openSetup
                )

                SettingsFlowCard(
                    title: "Connect Coding Agents",
                    subtitle: "OpenClaw, gateway ports, local helper state, and restart controls.",
                    systemImage: "network",
                    tint: .teal,
                    actionTitle: "Gateway",
                    action: openGateway
                )

                SettingsFlowCard(
                    title: "Turn On Protection",
                    subtitle: "Guardrail mode, scanner mode, runtime blocking, judge settings.",
                    systemImage: "shield.lefthalf.filled",
                    tint: .green,
                    actionTitle: "Guardrails",
                    action: openGuardrails
                )

                SettingsFlowCard(
                    title: "Triage a Finding",
                    subtitle: "Alerts, policy verdicts, allow/block decisions, and logs.",
                    systemImage: "bell.badge",
                    tint: .orange,
                    actionTitle: "Open Alerts",
                    action: openAlerts
                )
            }
        }
    }

    private var settingsByRole: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Settings by Role")
                .font(.title3.weight(.semibold))

            LazyVGrid(columns: [GridItem(.adaptive(minimum: 320), spacing: 12)], spacing: 12) {
                SettingsRoleCard(
                    title: "Security Admin",
                    items: [
                        SettingsRoleItem("Policy editor", "Rule packs, suppressions, regex rules, Rego", openPolicy),
                        SettingsRoleItem("Enforcement", "Allow, block, unblock, quarantine review", openEnforcement),
                        SettingsRoleItem("Guardrails", "Observe/action mode, judge settings, block message", openGuardrails)
                    ]
                )

                SettingsRoleCard(
                    title: "Platform Operator",
                    items: [
                        SettingsRoleItem("Diagnostics", "Backend health, doctor, logs, repair path", openDiagnostics),
                        SettingsRoleItem("Gateway", "Ports, sidecar restart, OpenClaw connection", openGateway),
                        SettingsRoleItem("Scanners", "Skill scanner, MCP scanner, CodeGuard binaries", openScanners)
                    ]
                )

                SettingsRoleCard(
                    title: "SecOps / Observability",
                    items: [
                        SettingsRoleItem("Logs", "Gateway, app, watchdog, and task logs", openLogs),
                        SettingsRoleItem("Config files", "Splunk, OTel, webhooks, Datadog-style sinks", openConfig),
                        SettingsRoleItem("Alerts", "Active findings and alert detail", openAlerts)
                    ]
                )
            }
        }
    }

    private var advancedAccess: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Advanced")
                .font(.title3.weight(.semibold))

            HStack(alignment: .top, spacing: 12) {
                SettingsFlowCard(
                    title: "Raw Config Editor",
                    subtitle: "Every discovered DefenseClaw, OpenClaw, scanner, and observability YAML/JSON file.",
                    systemImage: "doc.text.magnifyingglass",
                    tint: .purple,
                    actionTitle: "Config Files",
                    action: openConfig
                )

                SettingsFlowCard(
                    title: "System Diagnosis",
                    subtitle: "Use this when any flow fails, the helper is offline, or data is missing.",
                    systemImage: "stethoscope",
                    tint: .red,
                    actionTitle: "Diagnostics",
                    action: openDiagnostics
                )
            }
        }
    }
}

private struct SettingsFlowCard: View {
    let title: String
    let subtitle: String
    let systemImage: String
    let tint: Color
    let actionTitle: String
    let action: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(alignment: .top, spacing: 12) {
                Image(systemName: systemImage)
                    .font(.title2)
                    .foregroundStyle(tint)
                    .frame(width: 34, height: 34)
                    .background(tint.opacity(0.12), in: RoundedRectangle(cornerRadius: 8))

                VStack(alignment: .leading, spacing: 5) {
                    Text(title)
                        .font(.headline)
                    Text(subtitle)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }

            Spacer(minLength: 0)

            Button(action: action) {
                Label(actionTitle, systemImage: "arrow.right")
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.small)
        }
        .padding(14)
        .frame(maxWidth: .infinity, minHeight: 150, alignment: .leading)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 8))
    }
}

private struct SettingsRoleCard: View {
    let title: String
    let items: [SettingsRoleItem]

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(title)
                .font(.headline)

            ForEach(items) { item in
                Button(action: item.action) {
                    HStack(alignment: .top, spacing: 10) {
                        Image(systemName: "arrow.right.circle")
                            .foregroundStyle(.secondary)
                            .frame(width: 18)

                        VStack(alignment: .leading, spacing: 3) {
                            Text(item.title)
                                .font(.subheadline.weight(.semibold))
                            Text(item.subtitle)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                                .lineLimit(2)
                        }

                        Spacer()
                    }
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)

                if item.id != items.last?.id {
                    Divider()
                }
            }
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .topLeading)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 8))
    }
}

private struct SettingsRoleItem: Identifiable, Equatable {
    let id = UUID()
    let title: String
    let subtitle: String
    let action: () -> Void

    init(_ title: String, _ subtitle: String, _ action: @escaping () -> Void) {
        self.title = title
        self.subtitle = subtitle
        self.action = action
    }

    static func == (lhs: SettingsRoleItem, rhs: SettingsRoleItem) -> Bool {
        lhs.id == rhs.id
    }
}
