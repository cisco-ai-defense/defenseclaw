import SwiftUI
import DefenseClawKit

@main
struct DefenseClawApp: App {
    @State private var appViewModel = AppViewModel()

    var body: some Scene {
        WindowGroup {
            MainWindow()
                .environment(appViewModel)
        }
        .commands {
            CommandGroup(replacing: .newItem) {
                Button("New Session...") {
                    appViewModel.showNewSessionSheet = true
                }
                .keyboardShortcut("n", modifiers: [.command])
            }
        }

        Settings {
            SettingsView()
                .environment(appViewModel)
        }

        MenuBarExtra("DefenseClaw", systemImage: "shield.checkered") {
            MenuBarView()
                .environment(appViewModel)
        }
        .menuBarExtraStyle(.window)
    }
}
