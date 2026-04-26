import AppKit
import SwiftUI

class StatusBarController {
    private var statusItem: NSStatusItem?
    private var popover: NSPopover?
    let appViewModel: AppViewModel

    init(appViewModel: AppViewModel) {
        self.appViewModel = appViewModel
        setupStatusBar()
    }

    private func setupStatusBar() {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)

        if let button = statusItem?.button {
            button.image = NSImage(systemSymbolName: "shield.fill", accessibilityDescription: "DefenseClaw")
            button.action = #selector(statusBarButtonClicked)
            button.target = self
        }

        // Create popover
        popover = NSPopover()
        popover?.contentSize = NSSize(width: 250, height: 300)
        popover?.behavior = .transient
        popover?.contentViewController = NSHostingController(rootView: StatusBarPopover(appViewModel: appViewModel))
    }

    @objc private func statusBarButtonClicked() {
        guard let button = statusItem?.button else { return }

        if let popover = popover {
            if popover.isShown {
                popover.performClose(nil)
            } else {
                popover.show(relativeTo: button.bounds, of: button, preferredEdge: .minY)
            }
        }
    }
}
