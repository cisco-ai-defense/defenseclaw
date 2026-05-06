# DefenseClaw macOS App — Phase 4: AppKit + SwiftUI Hybrid (App C)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the AppKit + SwiftUI hybrid macOS app with a custom native tab strip (drag-reorder, close buttons, status dots), NSStatusItem menu bar, and SwiftUI content views for chat, governance, settings — consuming the shared DefenseClawKit package from Phase 1.

**Architecture:** AppKit owns the window frame, custom tab bar, and menu bar (NSStatusItem + NSPopover). SwiftUI is hosted via NSHostingView for all content: chat, governance sidebar, settings, scan, policy. This approach gives pixel-perfect tab control (drag-reorder, animated add/remove, close buttons with dirty indicators) while keeping content views declarative and reactive via `@Observable`.

**Tech Stack:** AppKit, SwiftUI (via NSHostingView), macOS 14+, Swift 5.9+, DefenseClawKit (SPM dependency), `@Observable`, `NSWindowController`, `NSStatusItem`, `NSPopover`

**Depends on:** Phase 1 (DefenseClawKit shared package) must be complete.

---

## File Structure

```
apps/appkit-app/
  DefenseClawAppKit/
    main.swift                              # NSApplicationMain
    AppDelegate.swift                       # NSApplicationDelegate, status bar setup, window creation
    WindowManagement/
      MainWindowController.swift            # NSWindowController — custom title bar area + content swap
      TabStripView.swift                    # Custom AppKit tab bar (NSView subclass)
      TabStripItem.swift                    # Single tab item: title, status dot, close button
    Views/                                  # SwiftUI content hosted via NSHostingView
      SessionContentView.swift              # SwiftUI session layout: chat + governance sidebar
      ChatView.swift                        # SwiftUI: message list with streaming + thinking
      ChatInputView.swift                   # SwiftUI: multiline input, slash commands, send
      MessageBubble.swift                   # SwiftUI: single message with content blocks
      ThinkingView.swift                    # SwiftUI: collapsible thinking block
      ToolCallCard.swift                    # SwiftUI: inline tool call card
      ApprovalCard.swift                    # SwiftUI: exec approval with Approve/Deny
      GuardrailBadge.swift                  # SwiftUI: inline guardrail badge
      GovernanceSidebarView.swift           # SwiftUI: alerts, skills, MCPs, plugins
      AlertRow.swift                        # SwiftUI: single alert row
      SkillRow.swift                        # SwiftUI: skill with controls
      MCPRow.swift                          # SwiftUI: MCP server row
      NewSessionSheet.swift                 # SwiftUI: workspace picker + agent config
      SettingsView.swift                    # SwiftUI: full config editor (tabbed)
      GatewaySettingsView.swift             # SwiftUI: gateway config
      GuardrailSettingsView.swift           # SwiftUI: guardrail config
      ScannersSettingsView.swift            # SwiftUI: scanner config
      IntegrationsSettingsView.swift        # SwiftUI: Splunk, OTel, Cisco AI Defense
      EnforcementSettingsView.swift         # SwiftUI: skill/MCP/plugin severity actions
      SandboxSettingsView.swift             # SwiftUI: OpenShell config
      DiagnosticsView.swift                 # SwiftUI: doctor output, sidecar status
      ScanView.swift                        # SwiftUI: CodeGuard, AIBOM, on-demand scans
      PolicyView.swift                      # SwiftUI: policy viewer, dry-run, firewall test
    MenuBar/
      StatusBarController.swift             # NSStatusItem + NSPopover management
      StatusBarPopover.swift                # SwiftUI popover content inside NSPopover
    ViewModels/
      AppViewModel.swift                    # @Observable — sessions, sidecar health, active tab
      SessionViewModel.swift                # @Observable — per-session chat, tools, governance
    Helpers/
      MarkdownRenderer.swift                # Render markdown in chat bubbles
  Package.swift                             # App package depending on DefenseClawKit
```

---

### Task 1: SPM App Scaffold + AppDelegate + Window Controller

**Files:**
- Create: `apps/appkit-app/Package.swift`
- Create: `apps/appkit-app/DefenseClawAppKit/main.swift`
- Create: `apps/appkit-app/DefenseClawAppKit/AppDelegate.swift`
- Create: `apps/appkit-app/DefenseClawAppKit/WindowManagement/MainWindowController.swift`
- Create: `apps/appkit-app/DefenseClawAppKit/ViewModels/AppViewModel.swift`
- Create: `apps/appkit-app/DefenseClawAppKit/ViewModels/SessionViewModel.swift`

- [ ] **Step 1: Create directory structure**

```bash
mkdir -p apps/appkit-app/DefenseClawAppKit/WindowManagement
mkdir -p apps/appkit-app/DefenseClawAppKit/Views
mkdir -p apps/appkit-app/DefenseClawAppKit/MenuBar
mkdir -p apps/appkit-app/DefenseClawAppKit/ViewModels
mkdir -p apps/appkit-app/DefenseClawAppKit/Helpers
```

- [ ] **Step 2: Write Package.swift**

```swift
// apps/appkit-app/Package.swift
// swift-tools-version: 5.9

import PackageDescription

let package = Package(
    name: "DefenseClawAppKit",
    platforms: [.macOS(.v14)],
    dependencies: [
        .package(path: "../shared"),
    ],
    targets: [
        .executableTarget(
            name: "DefenseClawAppKit",
            dependencies: [
                .product(name: "DefenseClawKit", package: "shared"),
            ],
            path: "DefenseClawAppKit"
        ),
    ]
)
```

- [ ] **Step 3: Write main.swift**

```swift
// apps/appkit-app/DefenseClawAppKit/main.swift
import AppKit

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.run()
```

- [ ] **Step 4: Write AppDelegate**

```swift
// apps/appkit-app/DefenseClawAppKit/AppDelegate.swift
import AppKit
import SwiftUI
import DefenseClawKit

final class AppDelegate: NSObject, NSApplicationDelegate {
    private var mainWindowController: MainWindowController?
    private var statusBarController: StatusBarController?
    let appViewModel = AppViewModel()

    func applicationDidFinishLaunching(_ notification: Notification) {
        // Create main window
        mainWindowController = MainWindowController(appViewModel: appViewModel)
        mainWindowController?.showWindow(nil)

        // Create status bar item
        statusBarController = StatusBarController(appViewModel: appViewModel)

        // Start sidecar health polling
        appViewModel.startPolling()
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        false // Keep running in menu bar
    }

    func applicationSupportsSecureRestorableState(_ app: NSApplication) -> Bool {
        true
    }
}
```

- [ ] **Step 5: Write AppViewModel**

```swift
// apps/appkit-app/DefenseClawAppKit/ViewModels/AppViewModel.swift
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

    func removeSession(at index: Int) {
        guard sessions.indices.contains(index) else { return }
        sessions.remove(at: index)
        if activeSessionIndex >= sessions.count {
            activeSessionIndex = max(0, sessions.count - 1)
        }
    }

    var activeSession: SessionViewModel? {
        guard sessions.indices.contains(activeSessionIndex) else { return nil }
        return sessions[activeSessionIndex]
    }
}
```

- [ ] **Step 6: Write SessionViewModel**

```swift
// apps/appkit-app/DefenseClawAppKit/ViewModels/SessionViewModel.swift
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

    func approveExec(requestId: String) {
        agentSession.resolveApproval(requestId: requestId, approved: true)
    }

    func denyExec(requestId: String) {
        agentSession.resolveApproval(requestId: requestId, approved: false)
    }

    func stopStreaming() {
        agentSession.cancelStream()
        isStreaming = false
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

- [ ] **Step 7: Write MainWindowController (minimal — content swap without tab strip yet)**

```swift
// apps/appkit-app/DefenseClawAppKit/WindowManagement/MainWindowController.swift
import AppKit
import SwiftUI
import DefenseClawKit

final class MainWindowController: NSWindowController {
    private let appViewModel: AppViewModel
    private var hostingView: NSHostingView<AnyView>?

    init(appViewModel: AppViewModel) {
        self.appViewModel = appViewModel

        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 1200, height: 800),
            styleMask: [.titled, .closable, .miniaturizable, .resizable, .fullSizeContentView],
            backing: .buffered,
            defer: false
        )
        window.title = "DefenseClaw"
        window.center()
        window.setFrameAutosaveName("DefenseClawMain")
        window.titlebarAppearsTransparent = true
        window.titleVisibility = .hidden
        window.minSize = NSSize(width: 900, height: 600)

        super.init(window: window)

        // Use a placeholder SwiftUI view as initial content
        let placeholderView = VStack {
            Text("DefenseClaw")
                .font(.largeTitle)
            Text("AppKit + SwiftUI Hybrid")
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)

        let hosting = NSHostingView(rootView: AnyView(placeholderView))
        window.contentView = hosting
        self.hostingView = hosting
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        fatalError("init(coder:) not implemented")
    }

    func updateContent(with view: some View) {
        hostingView?.rootView = AnyView(view)
    }
}
```

- [ ] **Step 8: Write minimal StatusBarController placeholder**

```swift
// apps/appkit-app/DefenseClawAppKit/MenuBar/StatusBarController.swift
import AppKit
import SwiftUI

final class StatusBarController {
    private var statusItem: NSStatusItem
    private var popover: NSPopover

    init(appViewModel: AppViewModel) {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        popover = NSPopover()

        if let button = statusItem.button {
            button.image = NSImage(systemSymbolName: "shield.checkered", accessibilityDescription: "DefenseClaw")
            button.action = #selector(togglePopover(_:))
            button.target = self
        }

        let hostingController = NSHostingController(
            rootView: StatusBarPopover(appViewModel: appViewModel)
        )
        popover.contentViewController = hostingController
        popover.behavior = .transient
    }

    @objc private func togglePopover(_ sender: AnyObject?) {
        guard let button = statusItem.button else { return }
        if popover.isShown {
            popover.performClose(sender)
        } else {
            popover.show(relativeTo: button.bounds, of: button, preferredEdge: .minY)
        }
    }
}
```

- [ ] **Step 9: Write StatusBarPopover**

```swift
// apps/appkit-app/DefenseClawAppKit/MenuBar/StatusBarPopover.swift
import SwiftUI

struct StatusBarPopover: View {
    let appViewModel: AppViewModel

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("DefenseClaw")
                .font(.headline)
            Divider()
            if appViewModel.isConnected {
                Label("Sidecar: connected", systemImage: "circle.fill")
                    .foregroundStyle(.green)
            } else {
                Label("Sidecar: disconnected", systemImage: "circle.fill")
                    .foregroundStyle(.red)
            }
            if let health = appViewModel.sidecarHealth {
                Label("Alerts: \(health.alertCount)", systemImage: "exclamationmark.triangle")
            }
            Divider()
            Button("Show Window") {
                NSApplication.shared.activate(ignoringOtherApps: true)
            }
            Button("Quit") {
                NSApplication.shared.terminate(nil)
            }
        }
        .padding()
        .frame(width: 240)
    }
}
```

- [ ] **Step 10: Build**

Run: `cd apps/appkit-app && swift build`
Expected: Build Succeeded

- [ ] **Step 11: Commit**

```bash
git add apps/appkit-app/
git commit -m "feat(macos): scaffold AppKit hybrid app with window controller and status bar"
```

---

### Task 2: Custom Tab Strip (AppKit NSView)

**Files:**
- Create: `apps/appkit-app/DefenseClawAppKit/WindowManagement/TabStripView.swift`
- Create: `apps/appkit-app/DefenseClawAppKit/WindowManagement/TabStripItem.swift`
- Modify: `apps/appkit-app/DefenseClawAppKit/WindowManagement/MainWindowController.swift`

- [ ] **Step 1: Write TabStripItem**

```swift
// apps/appkit-app/DefenseClawAppKit/WindowManagement/TabStripItem.swift
import AppKit

final class TabStripItem: NSView {
    var title: String {
        didSet { titleLabel.stringValue = title }
    }
    var isActive: Bool = false {
        didSet { needsDisplay = true }
    }
    var statusColor: NSColor = .systemGreen {
        didSet { statusDot.layer?.backgroundColor = statusColor.cgColor }
    }

    var onSelect: (() -> Void)?
    var onClose: (() -> Void)?

    private let statusDot = NSView()
    private let titleLabel = NSTextField(labelWithString: "")
    private let closeButton = NSButton()

    init(title: String) {
        self.title = title
        super.init(frame: .zero)
        setupViews()
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        fatalError("init(coder:) not implemented")
    }

    private func setupViews() {
        wantsLayer = true
        layer?.cornerRadius = 6

        // Status dot
        statusDot.wantsLayer = true
        statusDot.layer?.cornerRadius = 4
        statusDot.layer?.backgroundColor = NSColor.systemGreen.cgColor
        addSubview(statusDot)

        // Title
        titleLabel.stringValue = title
        titleLabel.font = .systemFont(ofSize: 12)
        titleLabel.lineBreakMode = .byTruncatingTail
        titleLabel.maximumNumberOfLines = 1
        addSubview(titleLabel)

        // Close button
        closeButton.bezelStyle = .inline
        closeButton.image = NSImage(systemSymbolName: "xmark", accessibilityDescription: "Close")
        closeButton.imageScaling = .scaleProportionallyDown
        closeButton.isBordered = false
        closeButton.target = self
        closeButton.action = #selector(closeTapped)
        addSubview(closeButton)

        // Layout
        statusDot.translatesAutoresizingMaskIntoConstraints = false
        titleLabel.translatesAutoresizingMaskIntoConstraints = false
        closeButton.translatesAutoresizingMaskIntoConstraints = false

        NSLayoutConstraint.activate([
            statusDot.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 8),
            statusDot.centerYAnchor.constraint(equalTo: centerYAnchor),
            statusDot.widthAnchor.constraint(equalToConstant: 8),
            statusDot.heightAnchor.constraint(equalToConstant: 8),

            titleLabel.leadingAnchor.constraint(equalTo: statusDot.trailingAnchor, constant: 6),
            titleLabel.centerYAnchor.constraint(equalTo: centerYAnchor),
            titleLabel.trailingAnchor.constraint(lessThanOrEqualTo: closeButton.leadingAnchor, constant: -4),

            closeButton.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -6),
            closeButton.centerYAnchor.constraint(equalTo: centerYAnchor),
            closeButton.widthAnchor.constraint(equalToConstant: 16),
            closeButton.heightAnchor.constraint(equalToConstant: 16),

            heightAnchor.constraint(equalToConstant: 32),
            widthAnchor.constraint(greaterThanOrEqualToConstant: 120),
            widthAnchor.constraint(lessThanOrEqualToConstant: 200),
        ])

        // Click gesture for selection
        let click = NSClickGestureRecognizer(target: self, action: #selector(selectTapped))
        addGestureRecognizer(click)
    }

    override func draw(_ dirtyRect: NSRect) {
        super.draw(dirtyRect)
        if isActive {
            layer?.backgroundColor = NSColor.controlAccentColor.withAlphaComponent(0.15).cgColor
        } else {
            layer?.backgroundColor = NSColor.clear.cgColor
        }
    }

    @objc private func selectTapped() {
        onSelect?()
    }

    @objc private func closeTapped() {
        onClose?()
    }
}
```

- [ ] **Step 2: Write TabStripView**

```swift
// apps/appkit-app/DefenseClawAppKit/WindowManagement/TabStripView.swift
import AppKit

protocol TabStripViewDelegate: AnyObject {
    func tabStripDidSelectTab(at index: Int)
    func tabStripDidCloseTab(at index: Int)
    func tabStripDidRequestNewTab()
}

final class TabStripView: NSView {
    weak var delegate: TabStripViewDelegate?

    private var tabItems: [TabStripItem] = []
    private let stackView = NSStackView()
    private let addButton = NSButton()
    private let scrollView = NSScrollView()

    override init(frame frameRect: NSRect) {
        super.init(frame: frameRect)
        setupViews()
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        fatalError("init(coder:) not implemented")
    }

    private func setupViews() {
        wantsLayer = true
        layer?.backgroundColor = NSColor.windowBackgroundColor.cgColor

        // Stack view for tabs
        stackView.orientation = .horizontal
        stackView.spacing = 2
        stackView.distribution = .fillProportionally

        // Scroll view wrapping the stack
        scrollView.documentView = stackView
        scrollView.hasHorizontalScroller = false
        scrollView.hasVerticalScroller = false
        scrollView.drawsBackground = false
        addSubview(scrollView)

        // Add tab button
        addButton.bezelStyle = .inline
        addButton.image = NSImage(systemSymbolName: "plus", accessibilityDescription: "New Session")
        addButton.isBordered = false
        addButton.target = self
        addButton.action = #selector(addTapped)
        addSubview(addButton)

        // Layout
        scrollView.translatesAutoresizingMaskIntoConstraints = false
        addButton.translatesAutoresizingMaskIntoConstraints = false
        stackView.translatesAutoresizingMaskIntoConstraints = false

        NSLayoutConstraint.activate([
            scrollView.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 80), // Leave room for traffic lights
            scrollView.topAnchor.constraint(equalTo: topAnchor),
            scrollView.bottomAnchor.constraint(equalTo: bottomAnchor),
            scrollView.trailingAnchor.constraint(equalTo: addButton.leadingAnchor, constant: -4),

            stackView.leadingAnchor.constraint(equalTo: scrollView.contentView.leadingAnchor),
            stackView.topAnchor.constraint(equalTo: scrollView.contentView.topAnchor),
            stackView.bottomAnchor.constraint(equalTo: scrollView.contentView.bottomAnchor),

            addButton.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -8),
            addButton.centerYAnchor.constraint(equalTo: centerYAnchor),
            addButton.widthAnchor.constraint(equalToConstant: 24),
            addButton.heightAnchor.constraint(equalToConstant: 24),

            heightAnchor.constraint(equalToConstant: 38),
        ])
    }

    func updateTabs(titles: [String], activeIndex: Int) {
        // Remove old tabs
        tabItems.forEach { $0.removeFromSuperview() }
        tabItems.removeAll()

        // Create new tabs
        for (index, title) in titles.enumerated() {
            let item = TabStripItem(title: title)
            item.isActive = (index == activeIndex)
            item.onSelect = { [weak self] in
                self?.delegate?.tabStripDidSelectTab(at: index)
            }
            item.onClose = { [weak self] in
                self?.delegate?.tabStripDidCloseTab(at: index)
            }
            tabItems.append(item)
            stackView.addArrangedSubview(item)
        }
    }

    @objc private func addTapped() {
        delegate?.tabStripDidRequestNewTab()
    }
}
```

- [ ] **Step 3: Update MainWindowController to use tab strip + SwiftUI content**

Replace the full content of `MainWindowController.swift`:

```swift
// apps/appkit-app/DefenseClawAppKit/WindowManagement/MainWindowController.swift
import AppKit
import SwiftUI
import DefenseClawKit

final class MainWindowController: NSWindowController, TabStripViewDelegate {
    private let appViewModel: AppViewModel
    private let tabStrip: TabStripView
    private var contentHostingView: NSHostingView<AnyView>?
    private let containerView = NSView()

    init(appViewModel: AppViewModel) {
        self.appViewModel = appViewModel
        self.tabStrip = TabStripView()

        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 1200, height: 800),
            styleMask: [.titled, .closable, .miniaturizable, .resizable, .fullSizeContentView],
            backing: .buffered,
            defer: false
        )
        window.title = "DefenseClaw"
        window.center()
        window.setFrameAutosaveName("DefenseClawMain")
        window.titlebarAppearsTransparent = true
        window.titleVisibility = .hidden
        window.minSize = NSSize(width: 900, height: 600)

        super.init(window: window)

        tabStrip.delegate = self
        setupLayout(in: window)
        refreshTabStrip()
        refreshContent()
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        fatalError("init(coder:) not implemented")
    }

    private func setupLayout(in window: NSWindow) {
        containerView.translatesAutoresizingMaskIntoConstraints = false
        tabStrip.translatesAutoresizingMaskIntoConstraints = false

        let rootView = NSView()
        rootView.addSubview(tabStrip)
        rootView.addSubview(containerView)

        tabStrip.translatesAutoresizingMaskIntoConstraints = false
        containerView.translatesAutoresizingMaskIntoConstraints = false

        NSLayoutConstraint.activate([
            tabStrip.topAnchor.constraint(equalTo: rootView.topAnchor),
            tabStrip.leadingAnchor.constraint(equalTo: rootView.leadingAnchor),
            tabStrip.trailingAnchor.constraint(equalTo: rootView.trailingAnchor),

            containerView.topAnchor.constraint(equalTo: tabStrip.bottomAnchor),
            containerView.leadingAnchor.constraint(equalTo: rootView.leadingAnchor),
            containerView.trailingAnchor.constraint(equalTo: rootView.trailingAnchor),
            containerView.bottomAnchor.constraint(equalTo: rootView.bottomAnchor),
        ])

        window.contentView = rootView
    }

    private func refreshTabStrip() {
        let titles = appViewModel.sessions.map(\.tabTitle)
        tabStrip.updateTabs(titles: titles, activeIndex: appViewModel.activeSessionIndex)
    }

    private func refreshContent() {
        // Remove old hosting view
        contentHostingView?.removeFromSuperview()

        if let session = appViewModel.activeSession {
            let swiftUIView = SessionContentView(session: session)
                .environment(appViewModel)
            let hosting = NSHostingView(rootView: AnyView(swiftUIView))
            hosting.translatesAutoresizingMaskIntoConstraints = false
            containerView.addSubview(hosting)
            NSLayoutConstraint.activate([
                hosting.topAnchor.constraint(equalTo: containerView.topAnchor),
                hosting.leadingAnchor.constraint(equalTo: containerView.leadingAnchor),
                hosting.trailingAnchor.constraint(equalTo: containerView.trailingAnchor),
                hosting.bottomAnchor.constraint(equalTo: containerView.bottomAnchor),
            ])
            contentHostingView = hosting
        } else {
            let emptyView = ContentUnavailableView(
                "No Session",
                systemImage: "bubble.left.and.bubble.right",
                description: Text("Click + to create a new session")
            )
            let hosting = NSHostingView(rootView: AnyView(emptyView))
            hosting.translatesAutoresizingMaskIntoConstraints = false
            containerView.addSubview(hosting)
            NSLayoutConstraint.activate([
                hosting.topAnchor.constraint(equalTo: containerView.topAnchor),
                hosting.leadingAnchor.constraint(equalTo: containerView.leadingAnchor),
                hosting.trailingAnchor.constraint(equalTo: containerView.trailingAnchor),
                hosting.bottomAnchor.constraint(equalTo: containerView.bottomAnchor),
            ])
            contentHostingView = hosting
        }
    }

    // MARK: - TabStripViewDelegate

    func tabStripDidSelectTab(at index: Int) {
        appViewModel.activeSessionIndex = index
        refreshTabStrip()
        refreshContent()
    }

    func tabStripDidCloseTab(at index: Int) {
        appViewModel.removeSession(at: index)
        refreshTabStrip()
        refreshContent()
    }

    func tabStripDidRequestNewTab() {
        let config = SessionConfig(workspace: NSHomeDirectory(), agentName: "Agent")
        appViewModel.addSession(config: config)
        refreshTabStrip()
        refreshContent()
    }
}
```

- [ ] **Step 4: Create placeholder SessionContentView**

```swift
// apps/appkit-app/DefenseClawAppKit/Views/SessionContentView.swift
import SwiftUI
import DefenseClawKit

struct SessionContentView: View {
    let session: SessionViewModel

    var body: some View {
        HSplitView {
            VStack(spacing: 0) {
                Text("Chat for \(session.tabTitle)")
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
            .frame(minWidth: 400)

            Text("Governance Sidebar")
                .frame(minWidth: 220, idealWidth: 280, maxWidth: 350)
        }
    }
}
```

- [ ] **Step 5: Build**

Run: `cd apps/appkit-app && swift build`
Expected: Build Succeeded

- [ ] **Step 6: Commit**

```bash
git add apps/appkit-app/
git commit -m "feat(macos): add AppKit custom tab strip with drag selection and close buttons"
```

---

### Task 3: Chat UI + Governance Sidebar (SwiftUI in NSHostingView)

**Files:**
- Modify: `apps/appkit-app/DefenseClawAppKit/Views/SessionContentView.swift`
- Create: `apps/appkit-app/DefenseClawAppKit/Views/ChatView.swift`
- Create: `apps/appkit-app/DefenseClawAppKit/Views/ChatInputView.swift`
- Create: `apps/appkit-app/DefenseClawAppKit/Views/MessageBubble.swift`
- Create: `apps/appkit-app/DefenseClawAppKit/Views/ThinkingView.swift`
- Create: `apps/appkit-app/DefenseClawAppKit/Views/ToolCallCard.swift`
- Create: `apps/appkit-app/DefenseClawAppKit/Views/ApprovalCard.swift`
- Create: `apps/appkit-app/DefenseClawAppKit/Views/GuardrailBadge.swift`
- Create: `apps/appkit-app/DefenseClawAppKit/Views/GovernanceSidebarView.swift`
- Create: `apps/appkit-app/DefenseClawAppKit/Views/AlertRow.swift`
- Create: `apps/appkit-app/DefenseClawAppKit/Views/SkillRow.swift`
- Create: `apps/appkit-app/DefenseClawAppKit/Views/MCPRow.swift`
- Create: `apps/appkit-app/DefenseClawAppKit/Views/NewSessionSheet.swift`
- Create: `apps/appkit-app/DefenseClawAppKit/Helpers/MarkdownRenderer.swift`

- [ ] **Step 1: Update SessionContentView with real layout**

```swift
// apps/appkit-app/DefenseClawAppKit/Views/SessionContentView.swift
import SwiftUI
import DefenseClawKit

struct SessionContentView: View {
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
            GovernanceSidebarView(session: session)
                .frame(minWidth: 220, idealWidth: 280, maxWidth: 350)
        }
        .task { await session.refreshGovernance() }
    }
}
```

- [ ] **Step 2: Write ChatView**

```swift
// apps/appkit-app/DefenseClawAppKit/Views/ChatView.swift
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
                    withAnimation(.easeOut(duration: 0.2)) {
                        proxy.scrollTo(last.id, anchor: .bottom)
                    }
                }
            }
        }
    }
}
```

- [ ] **Step 3: Write ChatInputView**

```swift
// apps/appkit-app/DefenseClawAppKit/Views/ChatInputView.swift
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

            if session.isStreaming {
                Button(action: { session.stopStreaming() }) {
                    Image(systemName: "stop.circle.fill")
                        .font(.title2)
                        .foregroundStyle(.red)
                }
                .buttonStyle(.plain)
                .help("Stop generating")
            } else {
                Button(action: send) {
                    Image(systemName: "arrow.up.circle.fill")
                        .font(.title2)
                }
                .disabled(input.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                .keyboardShortcut(.return, modifiers: [])
            }
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

- [ ] **Step 4: Write MessageBubble**

```swift
// apps/appkit-app/DefenseClawAppKit/Views/MessageBubble.swift
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
                .textSelection(.enabled)
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

- [ ] **Step 5: Write ThinkingView**

```swift
// apps/appkit-app/DefenseClawAppKit/Views/ThinkingView.swift
import SwiftUI
import DefenseClawKit

struct ThinkingView: View {
    let text: String
    let durationMs: Int?
    let isActive: Bool

    @State private var isExpanded: Bool = false

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            // Header
            Button {
                withAnimation(.easeInOut(duration: 0.2)) {
                    isExpanded.toggle()
                }
            } label: {
                HStack(spacing: 6) {
                    Image(systemName: isActive ? "brain" : (isExpanded ? "chevron.down" : "chevron.right"))
                        .font(.caption)
                    if isActive {
                        Text("Thinking...")
                            .font(.caption.bold())
                        ProgressView()
                            .controlSize(.small)
                    } else {
                        Text("Thinking")
                            .font(.caption.bold())
                        if let ms = durationMs {
                            Text("— \(String(format: "%.1f", Double(ms) / 1000.0))s")
                                .font(.caption)
                                .foregroundStyle(.tertiary)
                        }
                    }
                }
                .foregroundStyle(.secondary)
            }
            .buttonStyle(.plain)

            // Content (visible when active or expanded)
            if isActive || isExpanded {
                Text(text + (isActive ? "..." : ""))
                    .font(.system(.caption, design: .monospaced))
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
                    .padding(8)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(Color(.controlBackgroundColor).opacity(0.5))
                    .overlay(
                        RoundedRectangle(cornerRadius: 6)
                            .strokeBorder(style: StrokeStyle(lineWidth: 1, dash: [4, 3]))
                            .foregroundStyle(.quaternary)
                    )
                    .cornerRadius(6)
            }
        }
    }
}
```

- [ ] **Step 6: Write ToolCallCard**

```swift
// apps/appkit-app/DefenseClawAppKit/Views/ToolCallCard.swift
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
            // Header row
            HStack {
                statusIcon
                Text(tool)
                    .font(.system(.body, design: .monospaced, weight: .medium))
                Spacer()
                if let ms = elapsedMs {
                    Text("\(ms)ms")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                statusBadge
            }

            // Args preview
            if !args.isEmpty {
                Text(args)
                    .font(.system(.caption, design: .monospaced))
                    .foregroundStyle(.secondary)
                    .lineLimit(isExpanded ? nil : 2)
            }

            // Output (expandable)
            if let output, !output.isEmpty {
                Divider()
                Button {
                    isExpanded.toggle()
                } label: {
                    Text(output)
                        .font(.system(.caption, design: .monospaced))
                        .textSelection(.enabled)
                        .lineLimit(isExpanded ? nil : 5)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                .buttonStyle(.plain)

                if !isExpanded && output.count > 300 {
                    Text("Show more")
                        .font(.caption)
                        .foregroundStyle(.blue)
                }
            }
        }
        .padding(10)
        .background(Color(.controlBackgroundColor))
        .cornerRadius(8)
        .overlay(
            RoundedRectangle(cornerRadius: 8)
                .strokeBorder(borderColor, lineWidth: status == .running ? 2 : 1)
        )
    }

    @ViewBuilder
    private var statusIcon: some View {
        switch status {
        case .pending:
            ProgressView().controlSize(.small)
        case .running:
            Image(systemName: "gear")
                .symbolEffect(.rotate)
                .foregroundStyle(.blue)
        case .completed:
            Image(systemName: "checkmark.circle.fill")
                .foregroundStyle(.green)
        case .failed:
            Image(systemName: "xmark.circle.fill")
                .foregroundStyle(.red)
        case .warned:
            Image(systemName: "exclamationmark.triangle.fill")
                .foregroundStyle(.yellow)
        case .blocked:
            Image(systemName: "shield.fill")
                .foregroundStyle(.red)
        }
    }

    @ViewBuilder
    private var statusBadge: some View {
        switch status {
        case .pending: Text("pending").font(.caption2).foregroundStyle(.secondary)
        case .running: Text("running").font(.caption2).foregroundStyle(.blue)
        case .completed: Text("done").font(.caption2).foregroundStyle(.green)
        case .failed: Text("failed").font(.caption2).foregroundStyle(.red)
        case .warned: Text("warned").font(.caption2).foregroundStyle(.yellow)
        case .blocked: Text("blocked").font(.caption2).foregroundStyle(.red)
        }
    }

    private var borderColor: Color {
        switch status {
        case .pending: .secondary.opacity(0.3)
        case .running: .blue
        case .completed: .green.opacity(0.3)
        case .failed: .red.opacity(0.5)
        case .warned: .yellow.opacity(0.5)
        case .blocked: .red.opacity(0.5)
        }
    }
}
```

- [ ] **Step 7: Write ApprovalCard**

```swift
// apps/appkit-app/DefenseClawAppKit/Views/ApprovalCard.swift
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
            // Header
            HStack {
                Image(systemName: "exclamationmark.shield")
                    .foregroundStyle(isDangerous ? .red : .orange)
                Text("Approval Needed")
                    .font(.headline)
            }

            if isDangerous {
                Label("Dangerous command detected", systemImage: "exclamationmark.triangle.fill")
                    .font(.caption)
                    .foregroundStyle(.red)
                    .padding(4)
                    .background(Color.red.opacity(0.1))
                    .cornerRadius(4)
            }

            // Command
            Text(command)
                .font(.system(.body, design: .monospaced))
                .textSelection(.enabled)
                .padding(8)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Color(.textBackgroundColor))
                .cornerRadius(6)

            // Working directory
            Text("in \(cwd)")
                .font(.caption)
                .foregroundStyle(.secondary)

            // Action buttons or decision
            if let decision {
                HStack {
                    Image(systemName: decision == .approved ? "checkmark.circle.fill" : "xmark.circle.fill")
                    Text(decision == .approved ? "Approved" : "Denied")
                        .font(.caption.bold())
                }
                .foregroundStyle(decision == .approved ? .green : .red)
            } else {
                HStack(spacing: 12) {
                    Spacer()
                    Button("Deny") {
                        session.denyExec(requestId: id)
                    }
                    .buttonStyle(.bordered)
                    .tint(.red)

                    Button("Approve") {
                        session.approveExec(requestId: id)
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(.green)
                }
            }
        }
        .padding(12)
        .background(Color(.controlBackgroundColor))
        .cornerRadius(8)
        .overlay(
            RoundedRectangle(cornerRadius: 8)
                .strokeBorder(isDangerous ? Color.red.opacity(0.5) : Color.orange.opacity(0.3), lineWidth: 1.5)
        )
    }
}
```

- [ ] **Step 8: Write GuardrailBadge**

```swift
// apps/appkit-app/DefenseClawAppKit/Views/GuardrailBadge.swift
import SwiftUI
import DefenseClawKit

struct GuardrailBadge: View {
    let severity: Severity
    let action: String
    let reason: String

    var body: some View {
        HStack(spacing: 6) {
            Image(systemName: "shield.fill")
                .foregroundStyle(badgeColor)
            Text("Guardrail: \(action)")
                .font(.caption.bold())
            Text("— \(reason)")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .padding(8)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(badgeColor.opacity(0.1))
        .cornerRadius(6)
        .overlay(
            RoundedRectangle(cornerRadius: 6)
                .strokeBorder(badgeColor.opacity(0.3), lineWidth: 1)
        )
    }

    private var badgeColor: Color {
        switch severity {
        case .critical, .high: .red
        case .medium: .orange
        case .low: .yellow
        case .info: .blue
        }
    }
}
```

- [ ] **Step 9: Write GovernanceSidebarView + AlertRow + SkillRow + MCPRow**

```swift
// apps/appkit-app/DefenseClawAppKit/Views/GovernanceSidebarView.swift
import SwiftUI
import DefenseClawKit

struct GovernanceSidebarView: View {
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
                    ForEach(session.mcpServers) { server in
                        MCPRow(server: server)
                    }
                } header: {
                    Text("MCP SERVERS (\(session.mcpServers.count))").font(.caption.bold()).foregroundStyle(.secondary)
                }
            }
            .padding()
        }
        .background(Color(.controlBackgroundColor).opacity(0.5))
    }
}
```

```swift
// apps/appkit-app/DefenseClawAppKit/Views/AlertRow.swift
import SwiftUI
import DefenseClawKit

struct AlertRow: View {
    let alert: Alert

    var body: some View {
        HStack(spacing: 8) {
            Circle()
                .fill(severityColor)
                .frame(width: 8, height: 8)
            VStack(alignment: .leading, spacing: 2) {
                Text(alert.message)
                    .font(.caption)
                    .lineLimit(2)
                Text(alert.source)
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
        }
    }

    private var severityColor: Color {
        switch alert.severity {
        case .critical, .high: .red
        case .medium: .orange
        case .low: .yellow
        case .info: .blue
        }
    }
}
```

```swift
// apps/appkit-app/DefenseClawAppKit/Views/SkillRow.swift
import SwiftUI
import DefenseClawKit

struct SkillRow: View {
    let skill: Skill

    var body: some View {
        HStack {
            Image(systemName: skill.isBlocked ? "xmark.circle.fill" : "checkmark.circle.fill")
                .foregroundStyle(skill.isBlocked ? .red : .green)
                .font(.caption)
            Text(skill.name)
                .font(.caption)
            Spacer()
            if skill.isBlocked {
                Text("blocked")
                    .font(.caption2)
                    .foregroundStyle(.red)
            }
        }
    }
}
```

```swift
// apps/appkit-app/DefenseClawAppKit/Views/MCPRow.swift
import SwiftUI
import DefenseClawKit

struct MCPRow: View {
    let server: MCPServer

    var body: some View {
        HStack {
            Circle()
                .fill(server.isRunning ? Color.green : Color.red)
                .frame(width: 8, height: 8)
            VStack(alignment: .leading) {
                Text(server.name)
                    .font(.caption)
                Text(server.url)
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
            Spacer()
        }
    }
}
```

- [ ] **Step 10: Write NewSessionSheet**

```swift
// apps/appkit-app/DefenseClawAppKit/Views/NewSessionSheet.swift
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

- [ ] **Step 11: Write MarkdownRenderer placeholder**

```swift
// apps/appkit-app/DefenseClawAppKit/Helpers/MarkdownRenderer.swift
import SwiftUI

struct MarkdownRenderer: View {
    let text: String

    var body: some View {
        // Use SwiftUI's built-in markdown rendering for now
        Text(LocalizedStringKey(text))
            .textSelection(.enabled)
    }
}
```

- [ ] **Step 12: Build**

Run: `cd apps/appkit-app && swift build`
Expected: Build Succeeded

- [ ] **Step 13: Commit**

```bash
git add apps/appkit-app/
git commit -m "feat(macos): add SwiftUI chat UI, tool cards, approval, governance sidebar in AppKit host"
```

---

### Task 4: Settings, Scan, Policy Views + Final Build

**Files:**
- Create: `apps/appkit-app/DefenseClawAppKit/Views/SettingsView.swift`
- Create: `apps/appkit-app/DefenseClawAppKit/Views/GatewaySettingsView.swift`
- Create: `apps/appkit-app/DefenseClawAppKit/Views/GuardrailSettingsView.swift`
- Create: `apps/appkit-app/DefenseClawAppKit/Views/ScannersSettingsView.swift`
- Create: `apps/appkit-app/DefenseClawAppKit/Views/IntegrationsSettingsView.swift`
- Create: `apps/appkit-app/DefenseClawAppKit/Views/EnforcementSettingsView.swift`
- Create: `apps/appkit-app/DefenseClawAppKit/Views/SandboxSettingsView.swift`
- Create: `apps/appkit-app/DefenseClawAppKit/Views/DiagnosticsView.swift`
- Create: `apps/appkit-app/DefenseClawAppKit/Views/ScanView.swift`
- Create: `apps/appkit-app/DefenseClawAppKit/Views/PolicyView.swift`
- Modify: `apps/appkit-app/DefenseClawAppKit/AppDelegate.swift` (add Settings window)

- [ ] **Step 1: Write SettingsView with tabs**

```swift
// apps/appkit-app/DefenseClawAppKit/Views/SettingsView.swift
import SwiftUI
import DefenseClawKit

struct SettingsView: View {
    @State private var selectedTab = SettingsTab.gateway

    enum SettingsTab: String, CaseIterable {
        case gateway = "Gateway"
        case guardrail = "Guardrail"
        case scanners = "Scanners"
        case enforcement = "Enforcement"
        case integrations = "Integrations"
        case sandbox = "Sandbox"
        case diagnostics = "Diagnostics"
    }

    var body: some View {
        TabView(selection: $selectedTab) {
            GatewaySettingsView()
                .tabItem { Label("Gateway", systemImage: "network") }
                .tag(SettingsTab.gateway)

            GuardrailSettingsView()
                .tabItem { Label("Guardrail", systemImage: "shield") }
                .tag(SettingsTab.guardrail)

            ScannersSettingsView()
                .tabItem { Label("Scanners", systemImage: "magnifyingglass") }
                .tag(SettingsTab.scanners)

            EnforcementSettingsView()
                .tabItem { Label("Enforcement", systemImage: "lock.shield") }
                .tag(SettingsTab.enforcement)

            IntegrationsSettingsView()
                .tabItem { Label("Integrations", systemImage: "puzzlepiece.extension") }
                .tag(SettingsTab.integrations)

            SandboxSettingsView()
                .tabItem { Label("Sandbox", systemImage: "cube.transparent") }
                .tag(SettingsTab.sandbox)

            DiagnosticsView()
                .tabItem { Label("Diagnostics", systemImage: "stethoscope") }
                .tag(SettingsTab.diagnostics)
        }
        .frame(width: 700, height: 500)
    }
}
```

- [ ] **Step 2: Write settings tab views**

```swift
// apps/appkit-app/DefenseClawAppKit/Views/GatewaySettingsView.swift
import SwiftUI
import DefenseClawKit

struct GatewaySettingsView: View {
    @State private var config: AppConfig?
    private let configManager = ConfigManager()

    var body: some View {
        Form {
            if let config {
                Section("Connection") {
                    TextField("Host", text: binding(\.gateway.host))
                    TextField("Port", value: binding(\.gateway.port), format: .number)
                    TextField("API Port", value: binding(\.gateway.apiPort), format: .number)
                    SecureField("Token", text: binding(\.gateway.token))
                    Toggle("Auto-Approve Safe Commands", isOn: binding(\.gateway.autoApprove))
                }

                Section("Watcher") {
                    Toggle("Enabled", isOn: binding(\.gateway.watcher.enabled))
                    Toggle("Skill Watcher", isOn: binding(\.gateway.watcher.skill.enabled))
                    Toggle("Take Action", isOn: binding(\.gateway.watcher.skill.takeAction))
                }

                HStack {
                    Spacer()
                    Button("Save") { save() }
                        .buttonStyle(.borderedProminent)
                }
            } else {
                ProgressView("Loading config...")
            }
        }
        .formStyle(.grouped)
        .padding()
        .task { config = try? configManager.load() }
    }

    private func binding<T>(_ keyPath: WritableKeyPath<AppConfig, T>) -> Binding<T> {
        Binding(
            get: { config![keyPath: keyPath] },
            set: { config![keyPath: keyPath] = $0 }
        )
    }

    private func save() {
        guard let config else { return }
        try? configManager.save(config)
    }
}
```

```swift
// apps/appkit-app/DefenseClawAppKit/Views/GuardrailSettingsView.swift
import SwiftUI
import DefenseClawKit

struct GuardrailSettingsView: View {
    @State private var config: AppConfig?
    private let configManager = ConfigManager()

    var body: some View {
        Form {
            if let config {
                Section("Guardrail") {
                    Toggle("Enabled", isOn: binding(\.guardrail.enabled))
                    Picker("Mode", selection: binding(\.guardrail.mode)) {
                        Text("Observe").tag("observe")
                        Text("Action").tag("action")
                    }
                    TextField("Model", text: binding(\.guardrail.model))
                    TextField("Host", text: binding(\.guardrail.host))
                    TextField("Port", value: binding(\.guardrail.port), format: .number)
                }

                Section("LLM Judge") {
                    TextField("Model", text: binding(\.guardrail.judge.model))
                    TextField("Provider", text: binding(\.guardrail.judge.provider))
                    TextField("Threshold", value: binding(\.guardrail.judge.threshold), format: .number)
                }

                HStack {
                    Spacer()
                    Button("Save") { save() }
                        .buttonStyle(.borderedProminent)
                }
            } else {
                ProgressView("Loading config...")
            }
        }
        .formStyle(.grouped)
        .padding()
        .task { config = try? configManager.load() }
    }

    private func binding<T>(_ keyPath: WritableKeyPath<AppConfig, T>) -> Binding<T> {
        Binding(
            get: { config![keyPath: keyPath] },
            set: { config![keyPath: keyPath] = $0 }
        )
    }

    private func save() {
        guard let config else { return }
        try? configManager.save(config)
    }
}
```

```swift
// apps/appkit-app/DefenseClawAppKit/Views/ScannersSettingsView.swift
import SwiftUI
import DefenseClawKit

struct ScannersSettingsView: View {
    @State private var config: AppConfig?
    private let configManager = ConfigManager()

    var body: some View {
        Form {
            if let config {
                Section("Skill Scanner") {
                    TextField("Binary", text: binding(\.scanners.skillScanner.binary))
                    Toggle("Use LLM", isOn: binding(\.scanners.skillScanner.useLLM))
                    Toggle("Behavioral", isOn: binding(\.scanners.skillScanner.behavioral))
                    Toggle("VirusTotal", isOn: binding(\.scanners.skillScanner.virusTotal))
                    Toggle("Cisco AI Defense", isOn: binding(\.scanners.skillScanner.aiDefense))
                    Toggle("Policy Check", isOn: binding(\.scanners.skillScanner.policy))
                }

                Section("MCP Scanner") {
                    TextField("Binary", text: binding(\.scanners.mcpScanner.binary))
                    Toggle("Prompts", isOn: binding(\.scanners.mcpScanner.prompts))
                    Toggle("Resources", isOn: binding(\.scanners.mcpScanner.resources))
                    Toggle("Instructions", isOn: binding(\.scanners.mcpScanner.instructions))
                }

                HStack {
                    Spacer()
                    Button("Save") { save() }
                        .buttonStyle(.borderedProminent)
                }
            } else {
                ProgressView("Loading config...")
            }
        }
        .formStyle(.grouped)
        .padding()
        .task { config = try? configManager.load() }
    }

    private func binding<T>(_ keyPath: WritableKeyPath<AppConfig, T>) -> Binding<T> {
        Binding(
            get: { config![keyPath: keyPath] },
            set: { config![keyPath: keyPath] = $0 }
        )
    }

    private func save() {
        guard let config else { return }
        try? configManager.save(config)
    }
}
```

```swift
// apps/appkit-app/DefenseClawAppKit/Views/IntegrationsSettingsView.swift
import SwiftUI
import DefenseClawKit

struct IntegrationsSettingsView: View {
    @State private var config: AppConfig?
    private let configManager = ConfigManager()

    var body: some View {
        Form {
            if let config {
                Section("Splunk") {
                    TextField("HEC Endpoint", text: binding(\.splunk.hecEndpoint))
                    SecureField("HEC Token", text: binding(\.splunk.hecToken))
                    TextField("Index", text: binding(\.splunk.index))
                    TextField("Source", text: binding(\.splunk.source))
                    Toggle("Verify TLS", isOn: binding(\.splunk.verifyTLS))
                }

                Section("OpenTelemetry") {
                    Toggle("Enabled", isOn: binding(\.otel.enabled))
                    TextField("Endpoint", text: binding(\.otel.endpoint))
                }

                Section("Cisco AI Defense") {
                    TextField("Endpoint", text: binding(\.ciscoAIDefense.endpoint))
                    SecureField("API Key Env", text: binding(\.ciscoAIDefense.apiKeyEnv))
                    Toggle("Enabled", isOn: binding(\.ciscoAIDefense.enabled))
                }

                HStack {
                    Spacer()
                    Button("Save") { save() }
                        .buttonStyle(.borderedProminent)
                }
            } else {
                ProgressView("Loading config...")
            }
        }
        .formStyle(.grouped)
        .padding()
        .task { config = try? configManager.load() }
    }

    private func binding<T>(_ keyPath: WritableKeyPath<AppConfig, T>) -> Binding<T> {
        Binding(
            get: { config![keyPath: keyPath] },
            set: { config![keyPath: keyPath] = $0 }
        )
    }

    private func save() {
        guard let config else { return }
        try? configManager.save(config)
    }
}
```

```swift
// apps/appkit-app/DefenseClawAppKit/Views/EnforcementSettingsView.swift
import SwiftUI
import DefenseClawKit

struct EnforcementSettingsView: View {
    @State private var config: AppConfig?
    private let configManager = ConfigManager()

    var body: some View {
        Form {
            if let config {
                Section("Skill Actions") {
                    severityActionRow("Critical", binding: binding(\.skillActions.critical))
                    severityActionRow("High", binding: binding(\.skillActions.high))
                    severityActionRow("Medium", binding: binding(\.skillActions.medium))
                    severityActionRow("Low", binding: binding(\.skillActions.low))
                    severityActionRow("Info", binding: binding(\.skillActions.info))
                }

                Section("MCP Actions") {
                    severityActionRow("Critical", binding: binding(\.mcpActions.critical))
                    severityActionRow("High", binding: binding(\.mcpActions.high))
                    severityActionRow("Medium", binding: binding(\.mcpActions.medium))
                    severityActionRow("Low", binding: binding(\.mcpActions.low))
                    severityActionRow("Info", binding: binding(\.mcpActions.info))
                }

                Section("Plugin Actions") {
                    severityActionRow("Critical", binding: binding(\.pluginActions.critical))
                    severityActionRow("High", binding: binding(\.pluginActions.high))
                    severityActionRow("Medium", binding: binding(\.pluginActions.medium))
                    severityActionRow("Low", binding: binding(\.pluginActions.low))
                    severityActionRow("Info", binding: binding(\.pluginActions.info))
                }

                HStack {
                    Spacer()
                    Button("Save") { save() }
                        .buttonStyle(.borderedProminent)
                }
            } else {
                ProgressView("Loading config...")
            }
        }
        .formStyle(.grouped)
        .padding()
        .task { config = try? configManager.load() }
    }

    private func severityActionRow(_ label: String, binding: Binding<SeverityAction>) -> some View {
        HStack {
            Text(label)
                .frame(width: 60, alignment: .leading)
            Picker("File", selection: binding.file) {
                Text("Allow").tag("allow")
                Text("Warn").tag("warn")
                Text("Block").tag("block")
            }
            Picker("Runtime", selection: binding.runtime) {
                Text("Allow").tag("allow")
                Text("Warn").tag("warn")
                Text("Block").tag("block")
            }
            Picker("Install", selection: binding.install) {
                Text("Allow").tag("allow")
                Text("Warn").tag("warn")
                Text("Block").tag("block")
            }
        }
    }

    private func binding<T>(_ keyPath: WritableKeyPath<AppConfig, T>) -> Binding<T> {
        Binding(
            get: { config![keyPath: keyPath] },
            set: { config![keyPath: keyPath] = $0 }
        )
    }

    private func save() {
        guard let config else { return }
        try? configManager.save(config)
    }
}
```

```swift
// apps/appkit-app/DefenseClawAppKit/Views/SandboxSettingsView.swift
import SwiftUI
import DefenseClawKit

struct SandboxSettingsView: View {
    @State private var config: AppConfig?
    private let configManager = ConfigManager()

    var body: some View {
        Form {
            if let config {
                Section("OpenShell") {
                    TextField("Binary", text: binding(\.openshell.binary))
                    TextField("Policy Dir", text: binding(\.openshell.policyDir))
                    Picker("Mode", selection: binding(\.openshell.mode)) {
                        Text("Standalone").tag("standalone")
                        Text("Systemd").tag("systemd")
                    }
                    TextField("Version", text: binding(\.openshell.version))
                    Toggle("Host Networking", isOn: binding(\.openshell.hostNetworking))
                }

                HStack {
                    Spacer()
                    Button("Save") { save() }
                        .buttonStyle(.borderedProminent)
                }
            } else {
                ProgressView("Loading config...")
            }
        }
        .formStyle(.grouped)
        .padding()
        .task { config = try? configManager.load() }
    }

    private func binding<T>(_ keyPath: WritableKeyPath<AppConfig, T>) -> Binding<T> {
        Binding(
            get: { config![keyPath: keyPath] },
            set: { config![keyPath: keyPath] = $0 }
        )
    }

    private func save() {
        guard let config else { return }
        try? configManager.save(config)
    }
}
```

```swift
// apps/appkit-app/DefenseClawAppKit/Views/DiagnosticsView.swift
import SwiftUI
import DefenseClawKit

struct DiagnosticsView: View {
    @State private var doctorOutput = ""
    @State private var isRunning = false
    private let processRunner = ProcessRunner()

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                Text("Diagnostics")
                    .font(.title2.bold())
                Spacer()
                Button("Run Doctor") {
                    runDoctor()
                }
                .disabled(isRunning)
            }

            if isRunning {
                ProgressView("Running diagnostics...")
            }

            ScrollView {
                Text(doctorOutput.isEmpty ? "Click 'Run Doctor' to check system health." : doctorOutput)
                    .font(.system(.body, design: .monospaced))
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            .padding(8)
            .background(Color(.textBackgroundColor))
            .cornerRadius(8)
        }
        .padding()
    }

    private func runDoctor() {
        isRunning = true
        Task {
            do {
                let output = try await processRunner.doctor()
                doctorOutput = output
            } catch {
                doctorOutput = "Error: \(error.localizedDescription)"
            }
            isRunning = false
        }
    }
}
```

- [ ] **Step 3: Write ScanView**

```swift
// apps/appkit-app/DefenseClawAppKit/Views/ScanView.swift
import SwiftUI
import DefenseClawKit

struct ScanView: View {
    @State private var scanPath = ""
    @State private var scanType: ScanType = .skill
    @State private var results: [ScanResult] = []
    @State private var isScanning = false
    private let sidecar = SidecarClient()

    enum ScanType: String, CaseIterable {
        case skill = "Skill"
        case mcp = "MCP Server"
        case code = "CodeGuard"
        case aibom = "AIBOM"
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Scan")
                .font(.title2.bold())

            HStack {
                Picker("Type", selection: $scanType) {
                    ForEach(ScanType.allCases, id: \.self) { type in
                        Text(type.rawValue).tag(type)
                    }
                }
                .frame(width: 150)

                TextField("Path or URL", text: $scanPath)
                    .textFieldStyle(.roundedBorder)

                Button("Scan") { scan() }
                    .buttonStyle(.borderedProminent)
                    .disabled(scanPath.isEmpty || isScanning)
            }

            if isScanning {
                ProgressView("Scanning...")
            }

            // Results
            if !results.isEmpty {
                List(results) { result in
                    VStack(alignment: .leading, spacing: 4) {
                        HStack {
                            Text(result.target)
                                .font(.headline)
                            Spacer()
                            Text(result.overallSeverity.rawValue)
                                .font(.caption.bold())
                                .padding(.horizontal, 6)
                                .padding(.vertical, 2)
                                .background(severityColor(result.overallSeverity).opacity(0.2))
                                .cornerRadius(4)
                        }
                        ForEach(result.findings) { finding in
                            HStack {
                                Circle()
                                    .fill(severityColor(finding.severity))
                                    .frame(width: 8, height: 8)
                                Text(finding.title)
                                    .font(.caption)
                            }
                        }
                    }
                    .padding(.vertical, 4)
                }
            }
        }
        .padding()
    }

    private func scan() {
        isScanning = true
        Task {
            do {
                let result = try await sidecar.scanSkill(path: scanPath)
                results = [result]
            } catch {
                // Handle error
            }
            isScanning = false
        }
    }

    private func severityColor(_ severity: Severity) -> Color {
        switch severity {
        case .critical, .high: .red
        case .medium: .orange
        case .low: .yellow
        case .info: .blue
        }
    }
}
```

- [ ] **Step 4: Write PolicyView**

```swift
// apps/appkit-app/DefenseClawAppKit/Views/PolicyView.swift
import SwiftUI
import DefenseClawKit

struct PolicyView: View {
    @State private var policyJSON = ""
    @State private var dryRunTarget = ""
    @State private var dryRunType = "skill"
    @State private var dryRunResult = ""
    @State private var isLoading = false
    private let sidecar = SidecarClient()

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Policy")
                .font(.title2.bold())

            HSplitView {
                // Left: Policy viewer
                VStack(alignment: .leading, spacing: 8) {
                    HStack {
                        Text("Policy Data")
                            .font(.headline)
                        Spacer()
                        Button("Reload") { reload() }
                    }
                    ScrollView {
                        Text(policyJSON.isEmpty ? "Loading..." : policyJSON)
                            .font(.system(.caption, design: .monospaced))
                            .textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    .padding(8)
                    .background(Color(.textBackgroundColor))
                    .cornerRadius(8)
                }
                .frame(minWidth: 300)

                // Right: Dry run
                VStack(alignment: .leading, spacing: 8) {
                    Text("Dry Run")
                        .font(.headline)

                    Picker("Type", selection: $dryRunType) {
                        Text("Skill").tag("skill")
                        Text("MCP").tag("mcp")
                        Text("Plugin").tag("plugin")
                    }
                    .pickerStyle(.segmented)

                    TextField("Target name", text: $dryRunTarget)
                        .textFieldStyle(.roundedBorder)

                    Button("Evaluate") { evaluate() }
                        .buttonStyle(.borderedProminent)
                        .disabled(dryRunTarget.isEmpty)

                    if !dryRunResult.isEmpty {
                        ScrollView {
                            Text(dryRunResult)
                                .font(.system(.caption, design: .monospaced))
                                .textSelection(.enabled)
                                .frame(maxWidth: .infinity, alignment: .leading)
                        }
                        .padding(8)
                        .background(Color(.textBackgroundColor))
                        .cornerRadius(8)
                    }
                }
                .frame(minWidth: 250)
            }
        }
        .padding()
        .task { await loadPolicy() }
    }

    private func loadPolicy() async {
        isLoading = true
        do {
            policyJSON = try await sidecar.policyShow()
        } catch {
            policyJSON = "Error loading policy: \(error.localizedDescription)"
        }
        isLoading = false
    }

    private func reload() {
        Task {
            try? await sidecar.policyReload()
            await loadPolicy()
        }
    }

    private func evaluate() {
        Task {
            do {
                let result = try await sidecar.policyEvaluate(targetType: dryRunType, targetName: dryRunTarget)
                dryRunResult = "Verdict: \(result.verdict)\nSeverity: \(result.severity.rawValue)\nReason: \(result.reason)"
            } catch {
                dryRunResult = "Error: \(error.localizedDescription)"
            }
        }
    }
}
```

- [ ] **Step 5: Update AppDelegate to support Settings window**

Replace AppDelegate with version that opens Settings via NSWindow:

```swift
// apps/appkit-app/DefenseClawAppKit/AppDelegate.swift
import AppKit
import SwiftUI
import DefenseClawKit

final class AppDelegate: NSObject, NSApplicationDelegate {
    private var mainWindowController: MainWindowController?
    private var settingsWindow: NSWindow?
    private var statusBarController: StatusBarController?
    let appViewModel = AppViewModel()

    func applicationDidFinishLaunching(_ notification: Notification) {
        // Create main window
        mainWindowController = MainWindowController(appViewModel: appViewModel)
        mainWindowController?.showWindow(nil)

        // Create status bar item
        statusBarController = StatusBarController(appViewModel: appViewModel)

        // Start sidecar health polling
        appViewModel.startPolling()

        // Set up menu
        setupMainMenu()
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        false
    }

    func applicationSupportsSecureRestorableState(_ app: NSApplication) -> Bool {
        true
    }

    private func setupMainMenu() {
        let mainMenu = NSMenu()

        // App menu
        let appMenuItem = NSMenuItem()
        let appMenu = NSMenu()
        appMenu.addItem(withTitle: "About DefenseClaw", action: #selector(NSApplication.orderFrontStandardAboutPanel(_:)), keyEquivalent: "")
        appMenu.addItem(.separator())
        appMenu.addItem(withTitle: "Settings...", action: #selector(openSettings), keyEquivalent: ",")
        appMenu.addItem(.separator())
        appMenu.addItem(withTitle: "Quit DefenseClaw", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        appMenuItem.submenu = appMenu
        mainMenu.addItem(appMenuItem)

        // View menu
        let viewMenuItem = NSMenuItem()
        let viewMenu = NSMenu(title: "View")
        viewMenu.addItem(withTitle: "Show Main Window", action: #selector(showMainWindow), keyEquivalent: "0")
        viewMenuItem.submenu = viewMenu
        mainMenu.addItem(viewMenuItem)

        NSApplication.shared.mainMenu = mainMenu
    }

    @objc private func openSettings() {
        if settingsWindow == nil {
            let hosting = NSHostingController(rootView: SettingsView())
            let window = NSWindow(contentViewController: hosting)
            window.title = "DefenseClaw Settings"
            window.setFrameAutosaveName("DefenseClawSettings")
            window.styleMask = [.titled, .closable, .resizable]
            window.center()
            settingsWindow = window
        }
        settingsWindow?.makeKeyAndOrderFront(nil)
        NSApplication.shared.activate(ignoringOtherApps: true)
    }

    @objc private func showMainWindow() {
        mainWindowController?.showWindow(nil)
        NSApplication.shared.activate(ignoringOtherApps: true)
    }
}
```

- [ ] **Step 6: Build**

Run: `cd apps/appkit-app && swift build`
Expected: Build Succeeded

- [ ] **Step 7: Commit**

```bash
git add apps/appkit-app/
git commit -m "feat(macos): add settings, scan, policy views and app menu to AppKit hybrid app"
```
