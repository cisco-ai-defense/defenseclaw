import AppKit
import SwiftUI
import DefenseClawKit

class AppDelegate: NSObject, NSApplicationDelegate {
    var mainWindowController: MainWindowController?
    var statusBarController: StatusBarController?
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
            return OperatorSection(rawValue: arguments[index + 1])
        }

        if let argument = arguments.first(where: { $0.hasPrefix("--qa-section=") }) {
            return OperatorSection(rawValue: String(argument.dropFirst("--qa-section=".count)))
        }

        return nil
    }

    private func showSection(_ section: OperatorSection) {
        log.info("app", "Showing operator section", details: section.rawValue)
        mainWindowController?.showSection(section)
    }

    @objc func showHome() {
        showSection(.home)
    }

    @objc func showSettings() {
        showSection(.settings)
    }

    @objc func showScan() {
        showSection(.scan)
    }

    @objc func showPolicy() {
        showSection(.policy)
    }

    @objc func showAlerts() {
        showSection(.alerts)
    }

    @objc func showTools() {
        showSection(.tools)
    }

    @objc func showLogs() {
        showSection(.logs)
    }
}
