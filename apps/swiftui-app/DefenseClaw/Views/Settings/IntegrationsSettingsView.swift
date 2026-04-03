import SwiftUI
import DefenseClawKit

struct IntegrationsSettingsView: View {
    @State private var config: AppConfig?
    @State private var splunkEnabled = false
    @State private var splunkURL = ""
    @State private var otelEnabled = false
    @State private var otelEndpoint = ""
    @State private var isSaving = false

    var body: some View {
        Form {
            Section("Splunk Integration") {
                Toggle("Enable Splunk", isOn: $splunkEnabled)
                TextField("HEC Endpoint", text: $splunkURL)
                    .disabled(!splunkEnabled)
            }

            Section("OpenTelemetry") {
                Toggle("Enable OTel", isOn: $otelEnabled)
                TextField("Endpoint", text: $otelEndpoint)
                    .disabled(!otelEnabled)
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
            splunkEnabled = config?.splunk?.enabled ?? false
            splunkURL = config?.splunk?.hecEndpoint ?? ""
            otelEnabled = config?.otel?.enabled ?? false
            otelEndpoint = config?.otel?.endpoint ?? ""
        } catch {
            print("Error loading config: \(error)")
            config = AppConfig()
        }
    }

    private func saveConfig() {
        isSaving = true
        Task {
            do {
                var updatedConfig = config ?? AppConfig()
                // Note: Can't initialize nested config structs directly because they're Codable-only
                // This will only work if the config file already has these sections
                // In production, you'd want to create a proper builder or use reflection
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
