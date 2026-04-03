import AppKit
import SwiftUI

class MainWindowController: NSWindowController, TabStripViewDelegate {
    let appViewModel: AppViewModel
    var tabStripView: TabStripView!
    var contentView: NSView!
    var currentHostingView: NSHostingView<AnyView>?

    init(appViewModel: AppViewModel) {
        self.appViewModel = appViewModel

        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 1200, height: 800),
            styleMask: [.titled, .closable, .miniaturizable, .resizable, .fullSizeContentView],
            backing: .buffered,
            defer: false
        )
        window.titlebarAppearsTransparent = true
        window.titleVisibility = .hidden
        window.center()

        super.init(window: window)

        setupWindow()
        observeViewModel()
    }

    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    private func setupWindow() {
        guard let window = window else { return }

        // Create main container
        let containerView = NSView(frame: window.contentView!.bounds)
        containerView.autoresizingMask = [.width, .height]
        window.contentView?.addSubview(containerView)

        // Create tab strip in title bar area
        tabStripView = TabStripView(frame: NSRect(x: 0, y: containerView.bounds.height - 40, width: containerView.bounds.width, height: 40))
        tabStripView.autoresizingMask = [.width, .minYMargin]
        tabStripView.delegate = self
        containerView.addSubview(tabStripView)

        // Create content view below tab strip
        contentView = NSView(frame: NSRect(x: 0, y: 0, width: containerView.bounds.width, height: containerView.bounds.height - 40))
        contentView.autoresizingMask = [.width, .height]
        containerView.addSubview(contentView)

        updateContent()
    }

    private func observeViewModel() {
        // Observe changes to sessions
        Task { @MainActor in
            for await _ in NotificationCenter.default.notifications(named: NSNotification.Name("SessionsChanged")) {
                updateTabs()
            }
        }
    }

    private func updateTabs() {
        var tabs: [TabInfo] = []
        for (index, session) in appViewModel.sessions.enumerated() {
            let viewModel = SessionViewModel(session: session)
            let title = viewModel.tabTitle
            let isActive = index == appViewModel.activeSessionIndex
            let status: TabStatus = session.messages.last?.isStreaming == true ? .streaming : .idle
            tabs.append(TabInfo(title: title, isActive: isActive, status: status, index: index))
        }
        tabStripView.updateTabs(tabs)
    }

    private func updateContent() {
        currentHostingView?.removeFromSuperview()

        if let activeSession = appViewModel.activeSession {
            let viewModel = SessionViewModel(session: activeSession)
            let swiftUIView = SessionContentView(viewModel: viewModel)
                .environment(appViewModel)
            let hosting = NSHostingView(rootView: AnyView(swiftUIView))
            hosting.frame = contentView.bounds
            hosting.autoresizingMask = [.width, .height]
            contentView.addSubview(hosting)
            currentHostingView = hosting
        } else {
            let emptyView = VStack {
                Text("No Active Session")
                    .font(.title)
                    .foregroundStyle(.secondary)
                Button("New Session") {
                    self.appViewModel.showNewSessionSheet = true
                }
                .buttonStyle(.borderedProminent)
            }
            let hosting = NSHostingView(rootView: AnyView(emptyView))
            hosting.frame = contentView.bounds
            hosting.autoresizingMask = [.width, .height]
            contentView.addSubview(hosting)
            currentHostingView = hosting
        }
    }

    // MARK: - TabStripViewDelegate

    func tabStripView(_ view: TabStripView, didSelectTabAt index: Int) {
        appViewModel.activeSessionIndex = index
        updateContent()
    }

    func tabStripView(_ view: TabStripView, didCloseTabAt index: Int) {
        appViewModel.sessions.remove(at: index)
        if appViewModel.activeSessionIndex == index {
            appViewModel.activeSessionIndex = appViewModel.sessions.isEmpty ? nil : max(0, index - 1)
        } else if let active = appViewModel.activeSessionIndex, active > index {
            appViewModel.activeSessionIndex = active - 1
        }
        updateTabs()
        updateContent()
    }

    func tabStripViewDidRequestNewTab(_ view: TabStripView) {
        appViewModel.showNewSessionSheet = true
        showNewSessionSheet()
    }

    private func showNewSessionSheet() {
        let sheet = NewSessionSheet()
            .environment(appViewModel)
        let hostingController = NSHostingController(rootView: sheet)

        if let window = window {
            window.contentViewController?.presentAsSheet(hostingController)
        }
    }
}

struct TabInfo {
    let title: String
    let isActive: Bool
    let status: TabStatus
    let index: Int
}

enum TabStatus {
    case idle
    case streaming
    case error
}
