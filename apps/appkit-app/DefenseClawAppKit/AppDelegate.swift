import AppKit
import SwiftUI
import DefenseClawKit

class AppDelegate: NSObject, NSApplicationDelegate {
    var mainWindowController: MainWindowController?
    var statusBarController: StatusBarController?
    var settingsWindow: NSWindow?
    var scanWindow: NSWindow?
    var policyWindow: NSWindow?
    var appViewModel = AppViewModel()

    func applicationDidFinishLaunching(_ notification: Notification) {
        mainWindowController = MainWindowController(appViewModel: appViewModel)
        mainWindowController?.showWindow(nil)
        statusBarController = StatusBarController(appViewModel: appViewModel)
    }

    func applicationWillTerminate(_ notification: Notification) {}

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        return false
    }

    @objc func showSettings() {
        if settingsWindow == nil {
            let settingsView = SettingsView()
            let hostingController = NSHostingController(rootView: settingsView)
            let window = NSWindow(contentViewController: hostingController)
            window.title = "Settings"
            window.styleMask = [.titled, .closable]
            window.setContentSize(NSSize(width: 600, height: 500))
            window.center()
            settingsWindow = window
        }
        settingsWindow?.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    @objc func showScan() {
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
}
