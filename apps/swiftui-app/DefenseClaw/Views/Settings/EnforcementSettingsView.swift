import SwiftUI
import DefenseClawKit

struct EnforcementSettingsView: View {
    @State private var config: AppConfig?
    @State private var criticalAction = "block"
    @State private var highAction = "block"
    @State private var mediumAction = "warn"
    @State private var lowAction = "allow"
    @State private var isSaving = false

    private let actions = ["block", "warn", "allow"]

    var body: some View {
        Form {
            Section("Skill Enforcement Actions by Severity") {
                Picker("Critical", selection: $criticalAction) {
                    ForEach(actions, id: \.self) { action in
                        Text(action.capitalized).tag(action)
                    }
                }

                Picker("High", selection: $highAction) {
                    ForEach(actions, id: \.self) { action in
                        Text(action.capitalized).tag(action)
                    }
                }

                Picker("Medium", selection: $mediumAction) {
                    ForEach(actions, id: \.self) { action in
                        Text(action.capitalized).tag(action)
                    }
                }

                Picker("Low", selection: $lowAction) {
                    ForEach(actions, id: \.self) { action in
                        Text(action.capitalized).tag(action)
                    }
                }
            }

            HStack {
                Spacer()
                Button("Save") {
                    saveConfig()
                }
                .disabled(isSaving)
            }
        }
        .padding()
        .task {
            loadConfig()
        }
    }

    private func loadConfig() {
        let manager = ConfigManager()
        do {
            config = try manager.load()
            criticalAction = config?.skillActions?.critical?.install ?? "block"
            highAction = config?.skillActions?.high?.install ?? "block"
            mediumAction = config?.skillActions?.medium?.install ?? "warn"
            lowAction = config?.skillActions?.low?.install ?? "allow"
        } catch {
            print("Error loading config: \(error)")
            config = AppConfig()
        }
    }

    private func saveConfig() {
        isSaving = true
        Task {
            do {
                let updatedConfig = config ?? AppConfig()
                // Note: Settings are read-only in this UI for now
                let manager = ConfigManager()
                try manager.save(updatedConfig)
                config = updatedConfig
            } catch {
                print("Error saving config: \(error)")
            }
            isSaving = false
        }
    }
}
