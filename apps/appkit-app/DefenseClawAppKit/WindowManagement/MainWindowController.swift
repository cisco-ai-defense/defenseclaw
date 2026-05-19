import AppKit
import SwiftUI

class MainWindowController: NSWindowController {
    let appViewModel: AppViewModel
    let navigation = OperatorNavigationModel()

    init(appViewModel: AppViewModel) {
        self.appViewModel = appViewModel

        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 1280, height: 860),
            styleMask: [.titled, .closable, .miniaturizable, .resizable, .fullSizeContentView],
            backing: .buffered,
            defer: false
        )
        window.title = "DefenseClaw"
        window.titlebarAppearsTransparent = false
        window.titleVisibility = .visible
        window.center()

        super.init(window: window)

        setupWindow()
    }

    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    func showSection(_ section: OperatorSection) {
        navigation.selection = section
        showWindow(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    private func setupWindow() {
        guard let window else { return }
        let root = OperatorConsoleView(navigation: navigation)
            .environment(appViewModel)
        window.contentView = NSHostingView(rootView: root)
    }
}
