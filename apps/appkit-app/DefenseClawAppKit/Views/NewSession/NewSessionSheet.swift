import SwiftUI
import DefenseClawKit

struct NewSessionSheet: View {
    @Environment(AppViewModel.self) private var appViewModel
    @Environment(\.dismiss) private var dismiss
    @State private var workspace = ""
    @State private var agentName = ""
    @State private var isCreating = false
    @State private var error: String?

    var body: some View {
        Form {
            TextField("Workspace Path", text: $workspace)
                .textFieldStyle(.roundedBorder)

            TextField("Agent Name", text: $agentName)
                .textFieldStyle(.roundedBorder)

            if let error = error {
                Text(error)
                    .foregroundStyle(.red)
                    .font(.caption)
            }

            HStack {
                Button("Cancel") {
                    dismiss()
                }
                .keyboardShortcut(.cancelAction)

                Spacer()

                Button("Create") {
                    createSession()
                }
                .keyboardShortcut(.defaultAction)
                .disabled(workspace.isEmpty || agentName.isEmpty || isCreating)
            }
        }
        .padding()
        .frame(width: 400, height: 200)
    }

    private func createSession() {
        isCreating = true
        error = nil

        Task {
            do {
                try await appViewModel.addSession(workspace: workspace, agentName: agentName)
                await MainActor.run {
                    dismiss()
                }
            } catch {
                await MainActor.run {
                    self.error = error.localizedDescription
                    isCreating = false
                }
            }
        }
    }
}
