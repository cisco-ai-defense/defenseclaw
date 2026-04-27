import AppKit
import SwiftUI
import DefenseClawKit

class AppDelegate: NSObject, NSApplicationDelegate {
    var mainWindowController: MainWindowController?
    var statusBarController: StatusBarController?
    var settingsWindow: NSWindow?
    var scanWindow: NSWindow?
    var policyWindow: NSWindow?
    var toolsWindow: NSWindow?
    var alertsWindow: NSWindow?
    var logsWindow: NSWindow?
    var appViewModel = AppViewModel()

    private let log = AppLogger.shared

    func applicationDidFinishLaunching(_ notification: Notification) {
        log.info("app", "Application launched", details: "pid=\(ProcessInfo.processInfo.processIdentifier)")

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
        statusBarController = StatusBarController(appViewModel: appViewModel)
        log.info("app", "Main window and status bar ready")

        if ProcessInfo.processInfo.arguments.contains("--qa-open-all-windows") {
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) { [weak self] in
                self?.openAllQAWindows()
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

    private func openAllQAWindows() {
        showSettings()
        showScan()
        showPolicy()
        showAlerts()
        showTools()
        showLogs()
        mainWindowController?.showWindow(nil)
    }

    @objc func showSettings() {
        log.info("app", "Opening Settings window")
        if settingsWindow == nil {
            let settingsView = SettingsView()
            let hostingController = NSHostingController(rootView: settingsView)
            let window = NSWindow(contentViewController: hostingController)
            window.title = "Settings"
            window.styleMask = [.titled, .closable, .resizable]
            window.setContentSize(NSSize(width: 760, height: 620))
            window.minSize = NSSize(width: 700, height: 580)
            window.center()
            settingsWindow = window
        }
        settingsWindow?.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    @objc func showScan() {
        log.info("app", "Opening Scan window")
        if scanWindow == nil {
            let scanView = ScanView()
            let hostingController = NSHostingController(rootView: scanView)
            let window = NSWindow(contentViewController: hostingController)
            window.title = "Security Scan"
            window.styleMask = [.titled, .closable, .resizable]
            window.setContentSize(NSSize(width: 600, height: 500))
            window.center()
            scanWindow = window
        }
        scanWindow?.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    @objc func showPolicy() {
        log.info("app", "Opening Policy window")
        if policyWindow == nil {
            let policyView = PolicyView()
            let hostingController = NSHostingController(rootView: policyView)
            let window = NSWindow(contentViewController: hostingController)
            window.title = "Policies"
            window.styleMask = [.titled, .closable, .resizable]
            window.setContentSize(NSSize(width: 600, height: 500))
            window.center()
            policyWindow = window
        }
        policyWindow?.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    @objc func showAlerts() {
        log.info("app", "Opening Alerts window")
        if alertsWindow == nil {
            let alertsView = AlertsView()
            let hostingController = NSHostingController(rootView: alertsView)
            let window = NSWindow(contentViewController: hostingController)
            window.title = "Alerts"
            window.styleMask = [.titled, .closable, .resizable]
            window.setContentSize(NSSize(width: 700, height: 500))
            window.center()
            alertsWindow = window
        }
        alertsWindow?.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    @objc func showTools() {
        log.info("app", "Opening Tools window")
        if toolsWindow == nil {
            let toolsView = ToolsCatalogView()
            let hostingController = NSHostingController(rootView: toolsView)
            let window = NSWindow(contentViewController: hostingController)
            window.title = "Tools Catalog"
            window.styleMask = [.titled, .closable, .resizable]
            window.setContentSize(NSSize(width: 700, height: 600))
            window.center()
            toolsWindow = window
        }
        toolsWindow?.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    @objc func showLogs() {
        log.info("app", "Opening Logs window")
        if logsWindow == nil {
            let logsView = LogsView()
            let hostingController = NSHostingController(rootView: logsView)
            let window = NSWindow(contentViewController: hostingController)
            window.title = "Application Logs"
            window.styleMask = [.titled, .closable, .resizable]
            window.setContentSize(NSSize(width: 900, height: 600))
            window.center()
            logsWindow = window
        }
        logsWindow?.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }
}
