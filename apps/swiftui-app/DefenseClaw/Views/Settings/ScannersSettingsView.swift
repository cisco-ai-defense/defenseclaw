import SwiftUI
import DefenseClawKit

struct ScannersSettingsView: View {
    @State private var config: AppConfig?
    @State private var skillBinary = ""
    @State private var mcpBinary = ""
    @State private var codeguardBinary = ""
    @State private var isSaving = false

    var body: some View {
        Form {
            Section("Scanner Configuration") {
                TextField("Skill Scanner Binary", text: $skillBinary)
                TextField("MCP Scanner Binary", text: $mcpBinary)
                TextField("CodeGuard Binary", text: $codeguardBinary)
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
            skillBinary = config?.scanners?.skillScanner?.binary ?? ""
            mcpBinary = config?.scanners?.mcpScanner?.binary ?? ""
            codeguardBinary = config?.scanners?.codeguard ?? ""
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
