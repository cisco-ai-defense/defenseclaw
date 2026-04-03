import SwiftUI
import DefenseClawKit

struct SandboxSettingsView: View {
    @State private var config: AppConfig?
    @State private var binary = ""
    @State private var policyDir = ""
    @State private var mode = "permissive"
    @State private var isSaving = false

    var body: some View {
        Form {
            Section("OpenShell Sandbox Configuration") {
                TextField("Binary Path", text: $binary)
                TextField("Policy Directory", text: $policyDir)
                TextField("Mode", text: $mode)

                Text("Note: OpenShell sandbox is only available on Linux")
                    .font(.caption)
                    .foregroundStyle(.secondary)
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
            binary = config?.openshell?.binary ?? ""
            policyDir = config?.openshell?.policyDir ?? ""
            mode = config?.openshell?.mode ?? "permissive"
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
                // Note: Can't initialize nested config structs directly because they're Codable-only
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
