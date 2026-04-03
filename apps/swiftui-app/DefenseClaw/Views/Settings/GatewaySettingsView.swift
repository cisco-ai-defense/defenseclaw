import SwiftUI
import DefenseClawKit

struct GatewaySettingsView: View {
    @State private var config: AppConfig?
    @State private var port: String = ""
    @State private var host: String = ""
    @State private var isSaving = false

    var body: some View {
        Form {
            Section("Gateway Configuration") {
                TextField("Host", text: $host)
                TextField("Port", text: $port)
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
            host = config?.gateway?.host ?? "127.0.0.1"
            port = String(config?.gateway?.port ?? 18790)
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
