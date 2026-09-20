// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

import AppKit
import SwiftUI

extension View {
    /// Keeps a concise accessibility description beside the visual toolbar
    /// help supplied by `DCToolbarQuickHelpMonitor`.
    func dcQuickHelp(_ text: String) -> some View {
        accessibilityHint(Text(text))
    }
}

/// SwiftUI converts toolbar content into AppKit toolbar items and may discard
/// ordinary hover modifiers. Monitor the real toolbar item views so every page
/// gets the same short, predictable help delay.
final class DCToolbarQuickHelpMonitor {
    static let shared = DCToolbarQuickHelpMonitor()
    static let displayDelay: TimeInterval = 0.15

    private var eventMonitor: Any?
    private var observers: [NSObjectProtocol] = []
    private weak var currentAnchor: NSView?
    private var currentHelp: String?

    private init() {}

    func start() {
        guard eventMonitor == nil else { return }

        NSApp.windows.forEach(configure)
        let center = NotificationCenter.default
        observers.append(center.addObserver(
            forName: NSWindow.didBecomeKeyNotification,
            object: nil,
            queue: .main
        ) { [weak self] notification in
            guard let window = notification.object as? NSWindow else { return }
            self?.configure(window)
        })
        observers.append(center.addObserver(
            forName: NSWindow.didResignKeyNotification,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            self?.clearHover()
        })
        observers.append(center.addObserver(
            forName: NSApplication.didResignActiveNotification,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            self?.clearHover()
        })

        eventMonitor = NSEvent.addLocalMonitorForEvents(
            matching: [.mouseMoved, .leftMouseDown, .rightMouseDown, .scrollWheel]
        ) { [weak self] event in
            if event.type == .mouseMoved {
                self?.handleMouseMoved(event)
            } else {
                self?.clearHover()
            }
            return event
        }
    }

    private func configure(_ window: NSWindow) {
        window.acceptsMouseMovedEvents = true
    }

    private func handleMouseMoved(_ event: NSEvent) {
        guard NSApp.isActive,
              let window = event.window,
              window.isKeyWindow,
              let toolbar = window.toolbar,
              let match = matchingItem(
                  in: toolbar,
                  window: window,
                  windowPoint: event.locationInWindow
              )
        else {
            clearHover()
            return
        }

        if currentAnchor === match.view, currentHelp == match.help {
            return
        }

        currentAnchor = match.view
        currentHelp = match.help
        DCQuickHelpPresenter.shared.schedule(
            text: match.help,
            from: match.view,
            delay: Self.displayDelay
        )
    }

    private func matchingItem(
        in toolbar: NSToolbar,
        window: NSWindow,
        windowPoint: NSPoint
    ) -> (view: NSView, help: String)? {
        let items = (toolbar.visibleItems ?? []).flatMap(expandedItems)
        for item in items {
            guard let help = DCToolbarQuickHelpCatalog.text(
                windowTitle: window.title,
                itemLabel: item.label
            ),
            let view = item.view,
            view.window === window
            else { continue }

            let point = view.convert(windowPoint, from: nil)
            if view.bounds.insetBy(dx: -3, dy: -3).contains(point) {
                return (view, help)
            }
        }
        return nil
    }

    private func expandedItems(_ item: NSToolbarItem) -> [NSToolbarItem] {
        guard let group = item as? NSToolbarItemGroup else { return [item] }
        return group.subitems.flatMap(expandedItems)
    }

    private func clearHover() {
        currentAnchor = nil
        currentHelp = nil
        DCQuickHelpPresenter.shared.hide()
    }
}

private enum DCToolbarQuickHelpCatalog {
    private static let pageHelp: [String: [String: String]] = [
        "Overview": [
            "Run Health Check": "Run DefenseClaw Doctor",
            "Refresh": "Refresh overview",
        ],
        "Alerts": [
            "Acknowledge Selection": "Acknowledge selected alerts",
            "Refresh": "Refresh alerts",
        ],
        "Logs": [
            "Auto-scroll": "Follow new log lines",
            "Reload from disk": "Reload logs from disk",
        ],
        "Audit": [
            "Export JSON": "Export audit events as JSON",
            "Refresh": "Refresh audit events",
        ],
        "Activity": [
            "Run Command": "Open Command Palette",
            "Clear Completed": "Clear completed commands",
            "Refresh": "Refresh mutations",
        ],
        "Inventory": [
            "Rescan All": "Rescan connector inventories",
        ],
        "AI Discovery": [
            "Enable AI Discovery": "Enable AI Discovery",
            "Scan Now": "Scan this Mac for AI products and models",
            "Refresh": "Refresh AI Discovery results",
        ],
        "Registries": [
            "Add Source": "Add Registry Source",
            "Remove Source": "Remove Selected Source",
            "Approve": "Approve selected registry entry",
            "Reject": "Reject selected registry entry",
            "Require Registry": "Require Registry",
            "Make Registry Optional": "Make Registry Optional",
            "Sync Selected": "Sync selected registry source",
            "Sync All": "Sync all registry sources",
            "Refresh": "Refresh registries",
        ],
        "Skills": [
            "Install Skill": "Install a skill",
            "Refresh": "Refresh catalog",
        ],
        "MCPs": [
            "Set MCP Server": "Scan and add or update an MCP server",
            "Refresh": "Refresh catalog",
        ],
        "Plugins": [
            "Install Plugin": "Install a plugin",
            "Refresh": "Refresh catalog",
        ],
        "Tools": [
            "Refresh": "Refresh catalog",
        ],
    ]

    static func text(windowTitle: String, itemLabel: String) -> String? {
        if itemLabel == "Command Palette" {
            return "Command Palette (Command-Shift-P)"
        }
        return pageHelp[windowTitle]?[itemLabel]
    }
}

private final class DCQuickHelpPresenter {
    static let shared = DCQuickHelpPresenter()

    private let popover: NSPopover
    private var pendingPresentation: DispatchWorkItem?
    private weak var anchor: NSView?

    private init() {
        popover = NSPopover()
        popover.animates = false
        popover.behavior = .applicationDefined
    }

    func schedule(text: String, from anchor: NSView, delay: TimeInterval) {
        hide()
        self.anchor = anchor

        let presentation = DispatchWorkItem { [weak self, weak anchor] in
            guard let self, let anchor, self.anchor === anchor,
                  anchor.window?.isKeyWindow == true else { return }
            self.present(text: text, from: anchor)
        }
        pendingPresentation = presentation
        DispatchQueue.main.asyncAfter(
            deadline: .now() + max(0, delay),
            execute: presentation
        )
    }

    func hide() {
        pendingPresentation?.cancel()
        pendingPresentation = nil
        popover.close()
        anchor = nil
    }

    private func present(text: String, from anchor: NSView) {
        let controller = NSHostingController(
            rootView: Text(text)
                .font(.system(size: 12, weight: .medium))
                .lineLimit(2)
                .fixedSize(horizontal: true, vertical: true)
                .padding(.horizontal, 8)
                .padding(.vertical, 5)
                .accessibilityHidden(true)
        )
        controller.view.layoutSubtreeIfNeeded()
        popover.contentViewController = controller
        popover.contentSize = controller.view.fittingSize
        popover.show(relativeTo: anchor.bounds, of: anchor, preferredEdge: .minY)
    }
}
