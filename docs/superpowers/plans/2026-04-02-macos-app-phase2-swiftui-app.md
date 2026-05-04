# DefenseClaw macOS App — Phase 2: SwiftUI App (App A)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the pure SwiftUI macOS app with native chat interface (streaming + thinking), tab-based session management, governance sidebar, settings/config editor, and menu bar status — consuming the shared DefenseClawKit package from Phase 1.

**Architecture:** SwiftUI app targeting macOS 14+ using `@Observable` view models. `WindowGroup` for the main window, `MenuBarExtra` for ambient status. All data flows through `AppViewModel` (sidecar health, sessions) and per-tab `SessionViewModel` (chat, tools, governance).

**Tech Stack:** SwiftUI, macOS 14+, Swift 5.9+, DefenseClawKit (SPM dependency), `@Observable`, `TabView`, `NavigationSplitView`, `MenuBarExtra`, `SMAppService`

**Depends on:** Phase 1 (DefenseClawKit shared package) must be complete.

---

## File Structure

```
apps/swiftui-app/
  DefenseClaw/
    DefenseClawApp.swift              # @main, WindowGroup + MenuBarExtra + Settings
    ViewModels/
      AppViewModel.swift              # Sidecar health polling, session array, active tab
      SessionViewModel.swift          # Per-session: chat history, tool events, governance
    Views/
      MainWindow.swift                # Tab bar + content area (NavigationSplitView)
      Session/
        SessionTabView.swift          # Single session layout: chat + governance sidebar
        ChatView.swift                # Message list with streaming + thinking
        ChatInputView.swift           # Multiline input, slash commands, send button
        MessageBubble.swift           # Single message: text, thinking, tool call, approval
        ThinkingView.swift            # Collapsible thinking block with live streaming
        ToolCallCard.swift            # Inline tool call card (status, output, elapsed)
        ApprovalCard.swift            # Exec approval with Approve/Deny buttons
        GuardrailBadge.swift          # Inline guardrail block/warn badge
      Governance/
        GovernanceSidebar.swift       # Right sidebar: alerts, skills, MCPs, plugins
        AlertRow.swift                # Single alert row with severity badge
        SkillRow.swift                # Skill with enable/disable/block controls
        MCPRow.swift                  # MCP server with status
      Settings/
        SettingsView.swift            # Full config editor (tabbed)
        GatewaySettingsView.swift     # Gateway config section
        GuardrailSettingsView.swift   # Guardrail config section
        ScannersSettingsView.swift    # Scanner config section
        IntegrationsSettingsView.swift # Splunk, OTel, Cisco AI Defense
        EnforcementSettingsView.swift # Skill/MCP/Plugin severity actions
        SandboxSettingsView.swift     # OpenShell config
        DiagnosticsView.swift         # Doctor output, sidecar status
      Scan/
        ScanView.swift                # CodeGuard, AIBOM, on-demand scans
      Policy/
        PolicyView.swift              # Policy viewer, dry-run, firewall test
      NewSession/
        NewSessionSheet.swift         # Workspace picker + agent config
    MenuBar/
      MenuBarView.swift               # MenuBarExtra content
    Helpers/
      MarkdownRenderer.swift          # Render markdown in chat bubbles
  Package.swift                       # App package depending on DefenseClawKit
```

---

### Task 1: Xcode Project / SPM App Scaffold

**Files:**
- Create: `apps/swiftui-app/Package.swift`
- Create: `apps/swiftui-app/DefenseClaw/DefenseClawApp.swift`

- [ ] **Step 1: Create directory structure**

```bash
mkdir -p apps/swiftui-app/DefenseClaw/ViewModels
mkdir -p apps/swiftui-app/DefenseClaw/Views/Session
mkdir -p apps/swiftui-app/DefenseClaw/Views/Governance
mkdir -p apps/swiftui-app/DefenseClaw/Views/Settings
mkdir -p apps/swiftui-app/DefenseClaw/Views/Scan
mkdir -p apps/swiftui-app/DefenseClaw/Views/Policy
mkdir -p apps/swiftui-app/DefenseClaw/Views/NewSession
mkdir -p apps/swiftui-app/DefenseClaw/MenuBar
mkdir -p apps/swiftui-app/DefenseClaw/Helpers
```

- [ ] **Step 2: Write Package.swift**

```swift
// apps/swiftui-app/Package.swift
// swift-tools-version: 5.9

import PackageDescription

let package = Package(
    name: "DefenseClawApp",
    platforms: [.macOS(.v14)],
    dependencies: [
        .package(path: "../shared"),
    ],
    targets: [
        .executableTarget(
            name: "DefenseClaw",
            dependencies: [
                .product(name: "DefenseClawKit", package: "shared"),
            ],
            path: "DefenseClaw"
        ),
    ]
)
```

- [ ] **Step 3: Write the app entry point**

```swift
// apps/swiftui-app/DefenseClaw/DefenseClawApp.swift
import SwiftUI
import DefenseClawKit

@main
struct DefenseClawApp: App {
    @State private var appVM = AppViewModel()

    var body: some Scene {
        WindowGroup {
            MainWindow()
                .environment(appVM)
        }
        .defaultSize(width: 1200, height: 800)

        MenuBarExtra("DefenseClaw", systemImage: "shield.checkered") {
            MenuBarView()
                .environment(appVM)
        }

        Settings {
            SettingsView()
                .environment(appVM)
        }
    }
}
```

- [ ] **Step 4: Create placeholder views so it compiles**

Create minimal placeholder files for `MainWindow`, `MenuBarView`, `SettingsView`, and `AppViewModel`:

```swift
// apps/swiftui-app/DefenseClaw/ViewModels/AppViewModel.swift
import SwiftUI
import DefenseClawKit

@Observable
final class AppViewModel {
    var sessions: [SessionViewModel] = []
    var activeSessionIndex: Int = 0
    var sidecarHealth: HealthSnapshot?
    var isConnected = false

    private let sidecar = SidecarClient()

    func startPolling() {
        Task {
            while true {
                do {
                    sidecarHealth = try await sidecar.health()
                    isConnected = true
                } catch {
                    isConnected = false
                }
                try await Task.sleep(for: .seconds(5))
            }
        }
    }

    func addSession(config: SessionConfig) {
        let vm = SessionViewModel(config: config)
        sessions.append(vm)
        activeSessionIndex = sessions.count - 1
    }

    var activeSession: SessionViewModel? {
        guard sessions.indices.contains(activeSessionIndex) else { return nil }
        return sessions[activeSessionIndex]
    }
}
```

```swift
// apps/swiftui-app/DefenseClaw/ViewModels/SessionViewModel.swift
import SwiftUI
import DefenseClawKit

@Observable
final class SessionViewModel: Identifiable {
    let id = UUID()
    let config: SessionConfig
    var messages: [ChatMessage] = []
    var toolEvents: [ToolEvent] = []
    var alerts: [Alert] = []
    var skills: [Skill] = []
    var mcpServers: [MCPServer] = []
    var guardrailMode: String = "observe"
    var isStreaming = false

    private let agentSession: AgentSession
    private let sidecar = SidecarClient()

    init(config: SessionConfig) {
        self.config = config
        self.agentSession = AgentSession()
    }

    func sendMessage(_ text: String) {
        let msg = ChatMessage.text(text, role: .user)
        messages.append(msg)
        agentSession.sendMessage(text)
    }

    func refreshGovernance() async {
        do {
            alerts = try await sidecar.alerts()
            skills = try await sidecar.skills()
            mcpServers = try await sidecar.mcpServers()
            let gc = try await sidecar.guardrailConfig()
            guardrailMode = gc.mode
        } catch {
            // Governance data is best-effort
        }
    }

    var tabTitle: String {
        let name = config.agentName
        let workspace = URL(fileURLWithPath: config.workspace).lastPathComponent
        return "\(name): ~/\(workspace)"
    }
}
```

```swift
// apps/swiftui-app/DefenseClaw/Views/MainWindow.swift
import SwiftUI

struct MainWindow: View {
    @Environment(AppViewModel.self) private var appVM

    var body: some View {
        Text("DefenseClaw")
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .onAppear { appVM.startPolling() }
    }
}
```

```swift
// apps/swiftui-app/DefenseClaw/MenuBar/MenuBarView.swift
import SwiftUI

struct MenuBarView: View {
    @Environment(AppViewModel.self) private var appVM

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("DefenseClaw")
                .font(.headline)
            Divider()
            if appVM.isConnected {
                Label("Sidecar: connected", systemImage: "circle.fill")
                    .foregroundStyle(.green)
            } else {
                Label("Sidecar: disconnected", systemImage: "circle.fill")
                    .foregroundStyle(.red)
            }
            Divider()
            Button("Quit") { NSApplication.shared.terminate(nil) }
        }
        .padding()
        .frame(width: 220)
    }
}
```

```swift
// apps/swiftui-app/DefenseClaw/Views/Settings/SettingsView.swift
import SwiftUI

struct SettingsView: View {
    var body: some View {
        Text("Settings")
            .frame(width: 600, height: 400)
    }
}
```

- [ ] **Step 5: Build**

Run: `cd apps/swiftui-app && swift build`
Expected: Build Succeeded

- [ ] **Step 6: Commit**

```bash
git add apps/swiftui-app/
git commit -m "feat(macos): scaffold SwiftUI app with AppViewModel, SessionViewModel"
```

---

### Task 2: Tab Bar and Session Navigation

**Files:**
- Modify: `apps/swiftui-app/DefenseClaw/Views/MainWindow.swift`
- Create: `apps/swiftui-app/DefenseClaw/Views/NewSession/NewSessionSheet.swift`

- [ ] **Step 1: Build MainWindow with TabView**

```swift
// apps/swiftui-app/DefenseClaw/Views/MainWindow.swift
import SwiftUI

struct MainWindow: View {
    @Environment(AppViewModel.self) private var appVM
    @State private var showNewSession = false

    var body: some View {
        @Bindable var vm = appVM

        NavigationSplitView {
            // Left sidebar: navigation
            List {
                Section("Sessions") {
                    ForEach(Array(appVM.sessions.enumerated()), id: \.element.id) { index, session in
                        Button {
                            vm.activeSessionIndex = index
                        } label: {
                            Label(session.tabTitle, systemImage: "bubble.left.and.bubble.right")
                        }
                        .buttonStyle(.plain)
                        .padding(.vertical, 2)
                        .background(index == appVM.activeSessionIndex ? Color.accentColor.opacity(0.15) : Color.clear)
                        .cornerRadius(6)
                    }

                    Button {
                        showNewSession = true
                    } label: {
                        Label("New Session", systemImage: "plus")
                    }
                }

                Section("Tools") {
                    NavigationLink("Scan", value: NavDestination.scan)
                    NavigationLink("Policy", value: NavDestination.policy)
                }
            }
            .listStyle(.sidebar)
            .frame(minWidth: 180)
        } detail: {
            if let session = appVM.activeSession {
                SessionTabView(session: session)
            } else {
                ContentUnavailableView("No Session", systemImage: "bubble.left.and.bubble.right", description: Text("Create a new session to start"))
            }
        }
        .navigationTitle("DefenseClaw")
        .onAppear { appVM.startPolling() }
        .sheet(isPresented: $showNewSession) {
            NewSessionSheet { config in
                appVM.addSession(config: config)
                showNewSession = false
            }
        }
    }
}

enum NavDestination: Hashable {
    case scan
    case policy
}
```

- [ ] **Step 2: Write NewSessionSheet**

```swift
// apps/swiftui-app/DefenseClaw/Views/NewSession/NewSessionSheet.swift
import SwiftUI
import DefenseClawKit

struct NewSessionSheet: View {
    let onCreate: (SessionConfig) -> Void

    @State private var workspace = ""
    @State private var agentName = "Agent"
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(spacing: 16) {
            Text("New Agent Session")
                .font(.title2.bold())

            Form {
                TextField("Workspace Path", text: $workspace)
                    .textFieldStyle(.roundedBorder)
                TextField("Agent Name", text: $agentName)
                    .textFieldStyle(.roundedBorder)
            }
            .formStyle(.grouped)

            HStack {
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Spacer()
                Button("Create") {
                    let config = SessionConfig(workspace: workspace, agentName: agentName)
                    onCreate(config)
                }
                .keyboardShortcut(.defaultAction)
                .disabled(workspace.isEmpty)
            }
        }
        .padding()
        .frame(width: 400)
    }
}
```

- [ ] **Step 3: Create placeholder SessionTabView**

```swift
// apps/swiftui-app/DefenseClaw/Views/Session/SessionTabView.swift
import SwiftUI
import DefenseClawKit

struct SessionTabView: View {
    let session: SessionViewModel

    var body: some View {
        HSplitView {
            // Left: Chat + Tool Stream
            VStack(spacing: 0) {
                ChatView(session: session)
                ChatInputView(session: session)
            }
            .frame(minWidth: 400)

            // Right: Governance sidebar
            GovernanceSidebar(session: session)
                .frame(minWidth: 220, idealWidth: 280, maxWidth: 350)
        }
        .task { await session.refreshGovernance() }
    }
}
```

- [ ] **Step 4: Create minimal ChatView, ChatInputView, GovernanceSidebar placeholders**

```swift
// apps/swiftui-app/DefenseClaw/Views/Session/ChatView.swift
import SwiftUI
import DefenseClawKit

struct ChatView: View {
    let session: SessionViewModel

    var body: some View {
        ScrollViewReader { proxy in
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 12) {
                    ForEach(session.messages) { message in
                        MessageBubble(message: message, session: session)
                            .id(message.id)
                    }
                }
                .padding()
            }
            .onChange(of: session.messages.count) { _, _ in
                if let last = session.messages.last {
                    proxy.scrollTo(last.id, anchor: .bottom)
                }
            }
        }
    }
}
```

```swift
// apps/swiftui-app/DefenseClaw/Views/Session/ChatInputView.swift
import SwiftUI

struct ChatInputView: View {
    let session: SessionViewModel
    @State private var input = ""

    var body: some View {
        HStack(spacing: 8) {
            TextField("Type a message...", text: $input, axis: .vertical)
                .textFieldStyle(.plain)
                .lineLimit(1...5)
                .onSubmit { send() }

            Button(action: send) {
                Image(systemName: "arrow.up.circle.fill")
                    .font(.title2)
            }
            .disabled(input.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            .keyboardShortcut(.return, modifiers: [])
        }
        .padding(12)
        .background(.bar)
    }

    private func send() {
        let text = input.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty else { return }
        session.sendMessage(text)
        input = ""
    }
}
```

```swift
// apps/swiftui-app/DefenseClaw/Views/Session/MessageBubble.swift
import SwiftUI
import DefenseClawKit

struct MessageBubble: View {
    let message: ChatMessage
    let session: SessionViewModel

    var body: some View {
        VStack(alignment: message.role == .user ? .trailing : .leading, spacing: 4) {
            ForEach(message.blocks) { block in
                blockView(block)
            }
        }
        .frame(maxWidth: .infinity, alignment: message.role == .user ? .trailing : .leading)
    }

    @ViewBuilder
    private func blockView(_ block: ContentBlock) -> some View {
        switch block {
        case .text(_, let text):
            Text(text)
                .padding(10)
                .background(message.role == .user ? Color.accentColor.opacity(0.15) : Color(.controlBackgroundColor))
                .cornerRadius(12)

        case .thinking(_, let text, let durationMs):
            ThinkingView(text: text, durationMs: durationMs, isActive: message.isStreaming)

        case .toolCall(let id, let tool, let args, let status, let output, let elapsedMs):
            ToolCallCard(id: id, tool: tool, args: args, status: status, output: output, elapsedMs: elapsedMs)

        case .approvalRequest(let id, let command, let cwd, let isDangerous, let decision):
            ApprovalCard(id: id, command: command, cwd: cwd, isDangerous: isDangerous, decision: decision, session: session)

        case .guardrailBadge(_, let severity, let action, let reason):
            GuardrailBadge(severity: severity, action: action, reason: reason)
        }
    }
}
```

```swift
// apps/swiftui-app/DefenseClaw/Views/Governance/GovernanceSidebar.swift
import SwiftUI
import DefenseClawKit

struct GovernanceSidebar: View {
    let session: SessionViewModel

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                // Status
                Section {
                    Label("Guardrail: \(session.guardrailMode)", systemImage: "shield")
                } header: {
                    Text("STATUS").font(.caption.bold()).foregroundStyle(.secondary)
                }

                Divider()

                // Alerts
                Section {
                    if session.alerts.isEmpty {
                        Text("No alerts").foregroundStyle(.secondary)
                    } else {
                        ForEach(session.alerts) { alert in
                            AlertRow(alert: alert)
                        }
                    }
                } header: {
                    Text("ALERTS (\(session.alerts.count))").font(.caption.bold()).foregroundStyle(.secondary)
                }

                Divider()

                // Skills
                Section {
                    ForEach(session.skills) { skill in
                        SkillRow(skill: skill)
                    }
                } header: {
                    Text("SKILLS (\(session.skills.count))").font(.caption.bold()).foregroundStyle(.secondary)
                }

                Divider()

                // MCP Servers
                Section {
                    ForEach(session.mcpServers) { mcp in
                        MCPRow(mcp: mcp)
                    }
                } header: {
                    Text("MCP SERVERS (\(session.mcpServers.count))").font(.caption.bold()).foregroundStyle(.secondary)
                }
            }
            .padding()
        }
        .background(.background)
    }
}
```

- [ ] **Step 5: Create remaining placeholder views**

```swift
// apps/swiftui-app/DefenseClaw/Views/Session/ThinkingView.swift
import SwiftUI

struct ThinkingView: View {
    let text: String
    let durationMs: Int?
    let isActive: Bool
    @State private var isExpanded = false

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Button {
                withAnimation { isExpanded.toggle() }
            } label: {
                HStack {
                    Image(systemName: isExpanded || isActive ? "chevron.down" : "chevron.right")
                        .font(.caption)
                    if isActive {
                        ProgressView().controlSize(.small)
                        Text("Thinking...")
                    } else {
                        Text("Thinking")
                        if let ms = durationMs {
                            Text("- \(String(format: "%.1f", Double(ms) / 1000))s")
                                .foregroundStyle(.secondary)
                        }
                    }
                }
                .font(.caption)
                .foregroundStyle(.secondary)
            }
            .buttonStyle(.plain)

            if isExpanded || isActive {
                Text(text)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .padding(8)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(Color(.controlBackgroundColor).opacity(0.5))
                    .cornerRadius(6)
                    .overlay(
                        RoundedRectangle(cornerRadius: 6)
                            .strokeBorder(style: StrokeStyle(lineWidth: 1, dash: [4]))
                            .foregroundStyle(.quaternary)
                    )
            }
        }
    }
}
```

```swift
// apps/swiftui-app/DefenseClaw/Views/Session/ToolCallCard.swift
import SwiftUI
import DefenseClawKit

struct ToolCallCard: View {
    let id: String
    let tool: String
    let args: String
    let status: ToolCallStatus
    let output: String?
    let elapsedMs: Int?
    @State private var isExpanded = false

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                statusIcon
                Text(tool).font(.callout.monospaced().bold())
                Spacer()
                if let ms = elapsedMs {
                    Text("\(ms)ms").font(.caption).foregroundStyle(.secondary)
                }
                statusBadge
            }

            if !args.isEmpty {
                Text(args)
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
                    .lineLimit(isExpanded ? nil : 1)
            }

            if isExpanded, let output {
                Divider()
                ScrollView(.horizontal) {
                    Text(output)
                        .font(.caption.monospaced())
                        .textSelection(.enabled)
                }
                .frame(maxHeight: 200)
            }
        }
        .padding(10)
        .background(Color(.controlBackgroundColor))
        .cornerRadius(8)
        .overlay(
            RoundedRectangle(cornerRadius: 8)
                .strokeBorder(borderColor, lineWidth: 1)
        )
        .onTapGesture { withAnimation { isExpanded.toggle() } }
    }

    @ViewBuilder
    private var statusIcon: some View {
        switch status {
        case .pending: ProgressView().controlSize(.small)
        case .running: ProgressView().controlSize(.small)
        case .completed: Image(systemName: "checkmark.circle.fill").foregroundStyle(.green)
        case .failed: Image(systemName: "xmark.circle.fill").foregroundStyle(.red)
        case .warned: Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.yellow)
        case .blocked: Image(systemName: "shield.slash.fill").foregroundStyle(.red)
        }
    }

    @ViewBuilder
    private var statusBadge: some View {
        switch status {
        case .blocked: Text("BLOCKED").font(.caption2.bold()).foregroundStyle(.red)
        case .warned: Text("WARNED").font(.caption2.bold()).foregroundStyle(.yellow)
        default: EmptyView()
        }
    }

    private var borderColor: Color {
        switch status {
        case .running: return .blue.opacity(0.5)
        case .blocked: return .red.opacity(0.5)
        case .warned: return .yellow.opacity(0.5)
        default: return .clear
        }
    }
}
```

```swift
// apps/swiftui-app/DefenseClaw/Views/Session/ApprovalCard.swift
import SwiftUI
import DefenseClawKit

struct ApprovalCard: View {
    let id: String
    let command: String
    let cwd: String
    let isDangerous: Bool
    let decision: ApprovalDecision?
    let session: SessionViewModel

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Image(systemName: "exclamationmark.shield")
                    .foregroundStyle(isDangerous ? .red : .yellow)
                Text("Approval needed")
                    .font(.callout.bold())
            }

            Text(command)
                .font(.callout.monospaced())
                .textSelection(.enabled)

            if !cwd.isEmpty {
                Text("in \(cwd)")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            if isDangerous {
                Label("Dangerous command detected", systemImage: "exclamationmark.triangle.fill")
                    .font(.caption)
                    .foregroundStyle(.red)
            }

            if let decision {
                HStack {
                    switch decision {
                    case .approved:
                        Label("Approved", systemImage: "checkmark.circle.fill").foregroundStyle(.green)
                    case .denied:
                        Label("Denied", systemImage: "xmark.circle.fill").foregroundStyle(.red)
                    case .autoApproved:
                        Label("Auto-approved", systemImage: "checkmark.circle").foregroundStyle(.secondary)
                    }
                }
                .font(.caption)
            } else {
                HStack(spacing: 12) {
                    Spacer()
                    Button("Deny") {
                        Task { try? await session.resolveApproval(id: id, approved: false) }
                    }
                    .tint(.red)
                    Button("Approve") {
                        Task { try? await session.resolveApproval(id: id, approved: true) }
                    }
                    .tint(.green)
                    .buttonStyle(.borderedProminent)
                }
            }
        }
        .padding(12)
        .background(isDangerous ? Color.red.opacity(0.05) : Color.yellow.opacity(0.05))
        .cornerRadius(8)
        .overlay(
            RoundedRectangle(cornerRadius: 8)
                .strokeBorder(isDangerous ? Color.red.opacity(0.3) : Color.yellow.opacity(0.3))
        )
    }
}
```

```swift
// apps/swiftui-app/DefenseClaw/Views/Session/GuardrailBadge.swift
import SwiftUI

struct GuardrailBadge: View {
    let severity: String
    let action: String
    let reason: String

    var body: some View {
        HStack(spacing: 6) {
            Image(systemName: "shield.fill")
                .foregroundStyle(action == "block" ? .red : .yellow)
            Text("Guardrail: \(action)")
                .font(.callout.bold())
            Text("— \(reason)")
                .font(.callout)
                .foregroundStyle(.secondary)
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(action == "block" ? Color.red.opacity(0.08) : Color.yellow.opacity(0.08))
        .cornerRadius(8)
    }
}
```

```swift
// apps/swiftui-app/DefenseClaw/Views/Governance/AlertRow.swift
import SwiftUI
import DefenseClawKit

struct AlertRow: View {
    let alert: Alert

    var body: some View {
        HStack(spacing: 6) {
            Circle()
                .fill(severityColor)
                .frame(width: 8, height: 8)
            VStack(alignment: .leading) {
                Text(alert.action).font(.caption.bold())
                Text(alert.target).font(.caption).foregroundStyle(.secondary)
            }
        }
    }

    private var severityColor: Color {
        switch alert.severity {
        case .critical, .high: return .red
        case .medium: return .yellow
        case .low, .info: return .blue
        case .none: return .gray
        }
    }
}
```

```swift
// apps/swiftui-app/DefenseClaw/Views/Governance/SkillRow.swift
import SwiftUI
import DefenseClawKit

struct SkillRow: View {
    let skill: Skill

    var body: some View {
        HStack(spacing: 6) {
            Image(systemName: skill.blocked ? "xmark.circle.fill" : "checkmark.circle.fill")
                .foregroundStyle(skill.blocked ? .red : .green)
                .font(.caption)
            Text(skill.name).font(.caption)
            Spacer()
        }
    }
}
```

```swift
// apps/swiftui-app/DefenseClaw/Views/Governance/MCPRow.swift
import SwiftUI
import DefenseClawKit

struct MCPRow: View {
    let mcp: MCPServer

    var body: some View {
        HStack(spacing: 6) {
            Image(systemName: mcp.blocked ? "xmark.circle.fill" : "checkmark.circle.fill")
                .foregroundStyle(mcp.blocked ? .red : .green)
                .font(.caption)
            Text(mcp.name).font(.caption)
            Spacer()
        }
    }
}
```

```swift
// apps/swiftui-app/DefenseClaw/Views/Scan/ScanView.swift
import SwiftUI

struct ScanView: View {
    var body: some View {
        Text("Scan View — CodeGuard, AIBOM, On-demand scans")
            .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}
```

```swift
// apps/swiftui-app/DefenseClaw/Views/Policy/PolicyView.swift
import SwiftUI

struct PolicyView: View {
    var body: some View {
        Text("Policy View — OPA policies, dry-run, firewall test")
            .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}
```

```swift
// apps/swiftui-app/DefenseClaw/Helpers/MarkdownRenderer.swift
import SwiftUI

/// Renders markdown text as an AttributedString for chat messages.
struct MarkdownText: View {
    let text: String

    var body: some View {
        if let attributed = try? AttributedString(markdown: text, options: .init(interpretedSyntax: .inlineOnlyPreservingWhitespace)) {
            Text(attributed)
                .textSelection(.enabled)
        } else {
            Text(text)
                .textSelection(.enabled)
        }
    }
}
```

- [ ] **Step 6: Add resolveApproval to SessionViewModel**

Add this method to the existing `SessionViewModel`:

```swift
// Add to SessionViewModel
func resolveApproval(id: String, approved: Bool) async throws {
    try await agentSession.resolveApproval(id: id, approved: approved)
    // Update the approval block in messages
    for msgIdx in messages.indices {
        for blockIdx in messages[msgIdx].blocks.indices {
            if case .approvalRequest(let aId, let cmd, let cwd, let danger, _) = messages[msgIdx].blocks[blockIdx], aId == id {
                messages[msgIdx].blocks[blockIdx] = .approvalRequest(
                    id: id, command: cmd, cwd: cwd, isDangerous: danger,
                    decision: approved ? .approved : .denied
                )
                return
            }
        }
    }
}
```

- [ ] **Step 7: Build**

Run: `cd apps/swiftui-app && swift build`
Expected: Build Succeeded

- [ ] **Step 8: Commit**

```bash
git add apps/swiftui-app/
git commit -m "feat(macos): SwiftUI app with chat interface, tool cards, thinking, governance sidebar"
```

---

### Task 3: Settings / Config Editor

**Files:**
- Modify: `apps/swiftui-app/DefenseClaw/Views/Settings/SettingsView.swift`
- Create: `apps/swiftui-app/DefenseClaw/Views/Settings/GatewaySettingsView.swift`
- Create: `apps/swiftui-app/DefenseClaw/Views/Settings/GuardrailSettingsView.swift`
- Create: `apps/swiftui-app/DefenseClaw/Views/Settings/DiagnosticsView.swift`

- [ ] **Step 1: Write tabbed SettingsView**

```swift
// apps/swiftui-app/DefenseClaw/Views/Settings/SettingsView.swift
import SwiftUI
import DefenseClawKit

struct SettingsView: View {
    @State private var config: AppConfig = AppConfig()
    @State private var loadError: String?
    private let configManager = ConfigManager()

    var body: some View {
        TabView {
            GatewaySettingsView(config: $config)
                .tabItem { Label("Gateway", systemImage: "network") }

            GuardrailSettingsView(config: $config)
                .tabItem { Label("Guardrail", systemImage: "shield") }

            DiagnosticsView()
                .tabItem { Label("Diagnostics", systemImage: "stethoscope") }
        }
        .frame(width: 600, height: 450)
        .onAppear { loadConfig() }
        .toolbar {
            ToolbarItem(placement: .confirmationAction) {
                Button("Save") { saveConfig() }
            }
        }
    }

    private func loadConfig() {
        do {
            config = try configManager.load()
        } catch {
            loadError = error.localizedDescription
        }
    }

    private func saveConfig() {
        try? configManager.save(config)
    }
}
```

- [ ] **Step 2: Write GatewaySettingsView**

```swift
// apps/swiftui-app/DefenseClaw/Views/Settings/GatewaySettingsView.swift
import SwiftUI
import DefenseClawKit

struct GatewaySettingsView: View {
    @Binding var config: AppConfig

    var body: some View {
        Form {
            Section("Connection") {
                TextField("Host", text: binding(\.gateway?.host, default: "127.0.0.1"))
                TextField("Port", value: intBinding(\.gateway?.port, default: 18789), format: .number)
                TextField("API Port", value: intBinding(\.gateway?.apiPort, default: 18790), format: .number)
                Toggle("Auto-approve safe commands", isOn: boolBinding(\.gateway?.autoApproveSafe, default: false))
            }

            Section("Watcher") {
                Toggle("Enabled", isOn: boolBinding(\.gateway?.watcher?.enabled, default: true))
                Toggle("Skill watcher takes action", isOn: boolBinding(\.gateway?.watcher?.skill?.takeAction, default: false))
                Toggle("Plugin watcher takes action", isOn: boolBinding(\.gateway?.watcher?.plugin?.takeAction, default: false))
            }
        }
        .formStyle(.grouped)
    }

    // Helper to create bindings for optional nested properties
    private func binding(_ keyPath: WritableKeyPath<AppConfig, String?>, default defaultVal: String) -> Binding<String> {
        Binding(
            get: { config[keyPath: keyPath] ?? defaultVal },
            set: { config[keyPath: keyPath] = $0 }
        )
    }

    private func intBinding(_ keyPath: WritableKeyPath<AppConfig, Int?>, default defaultVal: Int) -> Binding<Int> {
        Binding(
            get: { config[keyPath: keyPath] ?? defaultVal },
            set: { config[keyPath: keyPath] = $0 }
        )
    }

    private func boolBinding(_ keyPath: WritableKeyPath<AppConfig, Bool?>, default defaultVal: Bool) -> Binding<Bool> {
        Binding(
            get: { config[keyPath: keyPath] ?? defaultVal },
            set: { config[keyPath: keyPath] = $0 }
        )
    }
}
```

- [ ] **Step 3: Write GuardrailSettingsView**

```swift
// apps/swiftui-app/DefenseClaw/Views/Settings/GuardrailSettingsView.swift
import SwiftUI
import DefenseClawKit

struct GuardrailSettingsView: View {
    @Binding var config: AppConfig

    var body: some View {
        Form {
            Section("Guardrail Proxy") {
                Toggle("Enabled", isOn: Binding(
                    get: { config.guardrail?.enabled ?? false },
                    set: { ensureGuardrail(); config.guardrail?.enabled = $0 }
                ))

                Picker("Mode", selection: Binding(
                    get: { config.guardrail?.mode ?? "observe" },
                    set: { ensureGuardrail(); config.guardrail?.mode = $0 }
                )) {
                    Text("Observe").tag("observe")
                    Text("Action").tag("action")
                }

                TextField("Model", text: Binding(
                    get: { config.guardrail?.model ?? "" },
                    set: { ensureGuardrail(); config.guardrail?.model = $0 }
                ))

                TextField("API Key Env Var", text: Binding(
                    get: { config.guardrail?.apiKeyEnv ?? "" },
                    set: { ensureGuardrail(); config.guardrail?.apiKeyEnv = $0 }
                ))
            }

            Section("LLM Judge") {
                Toggle("Judge enabled", isOn: Binding(
                    get: { config.guardrail?.judge?.enabled ?? false },
                    set: { ensureJudge(); config.guardrail?.judge?.enabled = $0 }
                ))
                Toggle("Injection detection", isOn: Binding(
                    get: { config.guardrail?.judge?.injection ?? true },
                    set: { ensureJudge(); config.guardrail?.judge?.injection = $0 }
                ))
                Toggle("PII detection", isOn: Binding(
                    get: { config.guardrail?.judge?.pii ?? true },
                    set: { ensureJudge(); config.guardrail?.judge?.pii = $0 }
                ))
            }
        }
        .formStyle(.grouped)
    }

    private func ensureGuardrail() {
        if config.guardrail == nil { config.guardrail = GuardrailFullConfig() }
    }

    private func ensureJudge() {
        ensureGuardrail()
        if config.guardrail?.judge == nil { config.guardrail?.judge = JudgeConfig() }
    }
}
```

- [ ] **Step 4: Write DiagnosticsView**

```swift
// apps/swiftui-app/DefenseClaw/Views/Settings/DiagnosticsView.swift
import SwiftUI
import DefenseClawKit

struct DiagnosticsView: View {
    @Environment(AppViewModel.self) private var appVM
    @State private var doctorOutput = ""
    @State private var isRunning = false
    private let runner = ProcessRunner()
    private let launchAgent = LaunchAgentManager()

    var body: some View {
        Form {
            Section("Sidecar") {
                if let health = appVM.sidecarHealth {
                    LabeledContent("Gateway", value: health.gateway.state.rawValue)
                    LabeledContent("Watcher", value: health.watcher.state.rawValue)
                    LabeledContent("API", value: health.api.state.rawValue)
                    LabeledContent("Guardrail", value: health.guardrail.state.rawValue)
                    LabeledContent("Uptime", value: "\(health.uptimeMs / 1000)s")
                } else {
                    Text("Not connected").foregroundStyle(.secondary)
                }
            }

            Section("LaunchAgent") {
                LabeledContent("Installed", value: launchAgent.isInstalled ? "Yes" : "No")
                LabeledContent("Running", value: launchAgent.isRunning ? "Yes" : "No")
            }

            Section("Doctor") {
                Button(isRunning ? "Running..." : "Run Diagnostics") {
                    Task { await runDoctor() }
                }
                .disabled(isRunning)

                if !doctorOutput.isEmpty {
                    Text(doctorOutput)
                        .font(.caption.monospaced())
                        .textSelection(.enabled)
                        .frame(maxHeight: 200)
                }
            }
        }
        .formStyle(.grouped)
    }

    private func runDoctor() async {
        isRunning = true
        defer { isRunning = false }
        do {
            let result = try await runner.doctor()
            doctorOutput = result.stdout + result.stderr
        } catch {
            doctorOutput = "Error: \(error.localizedDescription)"
        }
    }
}
```

- [ ] **Step 5: Build**

Run: `cd apps/swiftui-app && swift build`
Expected: Build Succeeded

- [ ] **Step 6: Commit**

```bash
git add apps/swiftui-app/DefenseClaw/Views/Settings/
git commit -m "feat(macos): add Settings views (Gateway, Guardrail, Diagnostics)"
```

---

### Task 4: Status Bar and Final Polish

**Files:**
- Modify: `apps/swiftui-app/DefenseClaw/DefenseClawApp.swift` (add status bar)
- Modify: `apps/swiftui-app/DefenseClaw/MenuBar/MenuBarView.swift` (expand)

- [ ] **Step 1: Expand MenuBarView with alert count and session info**

```swift
// apps/swiftui-app/DefenseClaw/MenuBar/MenuBarView.swift
import SwiftUI
import DefenseClawKit

struct MenuBarView: View {
    @Environment(AppViewModel.self) private var appVM

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("DefenseClaw").font(.headline)
            Text("v\(DefenseClawKit.version)").font(.caption).foregroundStyle(.secondary)

            Divider()

            if let health = appVM.sidecarHealth {
                subsystemRow("Gateway", state: health.gateway.state)
                subsystemRow("Watcher", state: health.watcher.state)
                subsystemRow("Guardrail", state: health.guardrail.state)
            } else {
                Label("Sidecar: offline", systemImage: "circle.fill")
                    .foregroundStyle(.red)
                    .font(.callout)
            }

            Divider()

            Text("\(appVM.sessions.count) session(s)")
                .font(.callout).foregroundStyle(.secondary)

            Divider()

            Button("Open DefenseClaw") {
                NSApplication.shared.activate(ignoringOtherApps: true)
            }
            Button("Quit") {
                NSApplication.shared.terminate(nil)
            }
        }
        .padding()
        .frame(width: 240)
    }

    private func subsystemRow(_ name: String, state: SubsystemState) -> some View {
        HStack(spacing: 6) {
            Circle()
                .fill(stateColor(state))
                .frame(width: 8, height: 8)
            Text(name).font(.callout)
            Spacer()
            Text(state.rawValue).font(.caption).foregroundStyle(.secondary)
        }
    }

    private func stateColor(_ state: SubsystemState) -> Color {
        switch state {
        case .running: return .green
        case .starting, .reconnecting: return .yellow
        case .disabled: return .gray
        case .error: return .red
        case .stopped: return .gray
        }
    }
}
```

- [ ] **Step 2: Build the final app**

Run: `cd apps/swiftui-app && swift build`
Expected: Build Succeeded

- [ ] **Step 3: Commit**

```bash
git add apps/swiftui-app/
git commit -m "feat(macos): complete SwiftUI app with menu bar, status, settings"
```

---

## Summary

| Task | Component | Key Files |
|------|-----------|-----------|
| 1 | App scaffold | Package.swift, DefenseClawApp.swift, AppViewModel, SessionViewModel |
| 2 | Tab bar + chat UI | MainWindow, SessionTabView, ChatView, MessageBubble, ThinkingView, ToolCallCard, ApprovalCard, GovernanceSidebar |
| 3 | Settings editor | SettingsView, GatewaySettings, GuardrailSettings, DiagnosticsView |
| 4 | Menu bar + polish | MenuBarView expansion, final build |

**Total: ~25 source files, 4 commits**

After Phase 2, App A is a functional SwiftUI app with:
- Multi-session tab management
- Native chat with streaming cursor, thinking panel, tool call cards, approval requests
- Governance sidebar (alerts, skills, MCPs)
- Settings editor for all config.yaml sections
- Menu bar status indicator
- LaunchAgent management
