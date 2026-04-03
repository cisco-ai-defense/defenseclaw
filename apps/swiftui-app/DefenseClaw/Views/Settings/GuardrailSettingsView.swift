import SwiftUI
import DefenseClawKit

struct GuardrailSettingsView: View {
    @State private var config: AppConfig?
    @State private var enabled = true
    @State private var mode = "proxy"
    @State private var isSaving = false

    var body: some View {
        Form {
            Section("Guardrail Configuration") {
                Toggle("Enable Guardrails", isOn: $enabled)
                TextField("Mode", text: $mode)
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
            enabled = config?.guardrail?.enabled ?? true
            mode = config?.guardrail?.mode ?? "proxy"
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
