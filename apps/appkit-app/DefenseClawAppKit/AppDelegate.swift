import AppKit
import SwiftUI
import DefenseClawKit

class AppDelegate: NSObject, NSApplicationDelegate {
    var mainWindowController: MainWindowController?
    var statusBarController: StatusBarController?
    var appViewModel = AppViewModel()

    private let log = AppLogger.shared
    private var engineVersion: String?

    func applicationDidFinishLaunching(_ notification: Notification) {
        log.info("app", "Application launched", details: "pid=\(ProcessInfo.processInfo.processIdentifier)")

        installMainMenu()

        // Ensure ~/.defenseclaw/ exists with default config (like `defenseclaw init`)
        do {
            try ConfigManager().ensureInitialized()
            log.info("app", "Config initialized")
        } catch {
            log.error("app", "Failed to initialize config", details: "\(error)")
        }

        // Install bundled policies if none exist on disk
        installBundledPolicies()

        mainWindowController = MainWindowController(appViewModel: appViewModel)
        mainWindowController?.showWindow(nil)
        NSApp.activate(ignoringOtherApps: true)
        statusBarController = StatusBarController(appViewModel: appViewModel)
        log.info("app", "Main window and status bar ready")

        if let qaSection = qaSectionArgument() {
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) { [weak self] in
                self?.showSection(qaSection)
            }
        }
    }

    func applicationWillTerminate(_ notification: Notification) {
        log.info("app", "Application terminating")
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        return false
    }

    private func installBundledPolicies() {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        let destDir = "\(home)/.defenseclaw/policies"
        let dataJSON = "\(destDir)/data.json"

        guard !FileManager.default.fileExists(atPath: dataJSON) else { return }

        guard let bundleResourcePath = Bundle.main.resourcePath else { return }
        let bundlePolicies = "\(bundleResourcePath)/policies"
        guard FileManager.default.fileExists(atPath: "\(bundlePolicies)/data.json") else { return }

        do {
            try FileManager.default.createDirectory(atPath: destDir, withIntermediateDirectories: true)
            let files = try FileManager.default.contentsOfDirectory(atPath: bundlePolicies)
            for file in files {
                let src = "\(bundlePolicies)/\(file)"
                let dst = "\(destDir)/\(file)"
                if !FileManager.default.fileExists(atPath: dst) {
                    try FileManager.default.copyItem(atPath: src, toPath: dst)
                }
            }
            log.info("app", "Installed bundled policies", details: destDir)
        } catch {
            log.error("app", "Failed to install policies", details: "\(error)")
        }
    }

    // MARK: - Window Management

    private func qaSectionArgument() -> OperatorSection? {
        let arguments = ProcessInfo.processInfo.arguments

        if let index = arguments.firstIndex(of: "--qa-section"),
           arguments.indices.contains(index + 1) {
            return operatorSection(for: arguments[index + 1])
        }

        if let argument = arguments.first(where: { $0.hasPrefix("--qa-section=") }) {
            return operatorSection(for: String(argument.dropFirst("--qa-section=".count)))
        }

        return nil
    }

    private func operatorSection(for rawValue: String) -> OperatorSection? {
        if let section = OperatorSection(rawValue: rawValue) {
            return section
        }

        switch rawValue {
        case "settings", "tools":
            return .advanced
        case "logs", "diagnostics":
            return .operations
        case "scans":
            return .scan
        default:
            return nil
        }
    }

    private func showSection(_ section: OperatorSection) {
        log.info("app", "Showing operator section", details: section.rawValue)
        mainWindowController?.showSection(section)
    }

    @objc func showHome() {
        showSection(.home)
    }

    @objc func showSetup() {
        showSection(.setup)
    }

    @objc func showSettings() {
        showSection(.advanced)
    }

    @objc func showProtection() {
        showSection(.protection)
    }

    @objc func showScan() {
        showSection(.scan)
    }

    @objc func showInventory() {
        showSection(.inventory)
    }

    @objc func showPolicy() {
        showSection(.policy)
    }

    @objc func showAlerts() {
        showSection(.alerts)
    }

    @objc func showTools() {
        showSection(.advanced)
    }

    @objc func showLogs() {
        showSection(.operations)
    }

    @objc func showOperations() {
        showSection(.operations)
    }

    @objc func showAdvanced() {
        showSection(.advanced)
    }

    // MARK: - Main menu

    /// Builds the application main menu. The app launches bare (no MainMenu.xib),
    /// so without this there are no standard App/Edit/Window commands and no
    /// keyboard navigation. The Go menu mirrors the TUI's number-key navigation.
    private func installMainMenu() {
        let mainMenu = NSMenu()

        // App menu
        let appItem = NSMenuItem()
        mainMenu.addItem(appItem)
        let appMenu = NSMenu()
        appItem.submenu = appMenu
        let aboutItem = appMenu.addItem(withTitle: "About DefenseClaw", action: #selector(showAboutPanel), keyEquivalent: "")
        aboutItem.target = self
        appMenu.addItem(.separator())
        appMenu.addItem(withTitle: "Hide DefenseClaw", action: #selector(NSApplication.hide(_:)), keyEquivalent: "h")
        let hideOthers = appMenu.addItem(withTitle: "Hide Others", action: #selector(NSApplication.hideOtherApplications(_:)), keyEquivalent: "h")
        hideOthers.keyEquivalentModifierMask = [.command, .option]
        appMenu.addItem(withTitle: "Show All", action: #selector(NSApplication.unhideAllApplications(_:)), keyEquivalent: "")
        appMenu.addItem(.separator())
        appMenu.addItem(withTitle: "Quit DefenseClaw", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")

        // Edit menu (standard editing via the responder chain)
        let editItem = NSMenuItem()
        mainMenu.addItem(editItem)
        let editMenu = NSMenu(title: "Edit")
        editItem.submenu = editMenu
        editMenu.addItem(withTitle: "Undo", action: Selector(("undo:")), keyEquivalent: "z")
        let redo = editMenu.addItem(withTitle: "Redo", action: Selector(("redo:")), keyEquivalent: "z")
        redo.keyEquivalentModifierMask = [.command, .shift]
        editMenu.addItem(.separator())
        editMenu.addItem(withTitle: "Cut", action: #selector(NSText.cut(_:)), keyEquivalent: "x")
        editMenu.addItem(withTitle: "Copy", action: #selector(NSText.copy(_:)), keyEquivalent: "c")
        editMenu.addItem(withTitle: "Paste", action: #selector(NSText.paste(_:)), keyEquivalent: "v")
        editMenu.addItem(withTitle: "Select All", action: #selector(NSText.selectAll(_:)), keyEquivalent: "a")

        // Go menu — keyboard navigation to each section (parity with TUI number keys)
        let goItem = NSMenuItem()
        mainMenu.addItem(goItem)
        let goMenu = NSMenu(title: "Go")
        goItem.submenu = goMenu
        let sections: [(String, Selector, String)] = [
            ("Home", #selector(showHome), "1"),
            ("Setup", #selector(showSetup), "2"),
            ("Scans", #selector(showScan), "3"),
            ("Protection", #selector(showProtection), "4"),
            ("Policy", #selector(showPolicy), "5"),
            ("Alerts", #selector(showAlerts), "6"),
            ("Tools", #selector(showTools), "7"),
            ("Logs", #selector(showLogs), "8"),
            ("Inventory", #selector(showInventory), "9")
        ]
        for (title, action, key) in sections {
            let item = goMenu.addItem(withTitle: title, action: action, keyEquivalent: key)
            item.target = self
        }

        // Window menu
        let windowItem = NSMenuItem()
        mainMenu.addItem(windowItem)
        let windowMenu = NSMenu(title: "Window")
        windowItem.submenu = windowMenu
        windowMenu.addItem(withTitle: "Minimize", action: #selector(NSWindow.performMiniaturize(_:)), keyEquivalent: "m")
        windowMenu.addItem(withTitle: "Zoom", action: #selector(NSWindow.performZoom(_:)), keyEquivalent: "")
        NSApp.windowsMenu = windowMenu

        NSApp.mainMenu = mainMenu
        refreshEngineVersion()
    }

    /// Fetches the DefenseClaw engine (gateway) version asynchronously and
    /// updates its menu item. Kept distinct from the macOS app bundle version.
    private func refreshEngineVersion() {
        Task { [weak self] in
            let version = await Self.fetchEngineVersion()
            await MainActor.run {
                self?.engineVersion = version
            }
        }
    }

    /// Custom About panel showing both the macOS app bundle version and the
    /// distinct DefenseClaw engine (gateway/CLI) version.
    @objc private func showAboutPanel() {
        let appVersion = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "—"
        let credits = NSAttributedString(
            string: "DefenseClaw Engine \(engineVersion ?? "checking…")",
            attributes: [
                .font: NSFont.systemFont(ofSize: 11),
                .foregroundColor: NSColor.secondaryLabelColor
            ]
        )
        NSApp.orderFrontStandardAboutPanel(options: [
            .applicationVersion: appVersion,
            .credits: credits
        ])
    }

    private static func fetchEngineVersion() async -> String? {
        guard let result = try? await LocalCommandRunner().run("defenseclaw-gateway", arguments: ["--version"]),
              result.exitCode == 0 else {
            return nil
        }
        // e.g. "defenseclaw-gateway version 0.6.1+local-7bdc2ca (commit=…, built=…)"
        let output = result.standardOutput
        if let range = output.range(of: "version ") {
            let rest = output[range.upperBound...]
            if let token = rest.split(whereSeparator: { $0 == " " || $0 == "\n" }).first {
                return String(token)
            }
        }
        return output.split(separator: "\n").first.map { String($0).trimmingCharacters(in: .whitespaces) }
    }
}
