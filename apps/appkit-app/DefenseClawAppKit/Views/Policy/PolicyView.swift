import SwiftUI
import DefenseClawKit

struct PolicyView: View {
    @State private var policyContent = ""
    @State private var isLoading = false
    @State private var isDryRun = false
    @State private var dryRunResults = ""
    @State private var error: String?
    @State private var evalTargetType = "skill"
    @State private var evalTargetName = ""

    private let targetTypes = ["skill", "mcp", "plugin"]

    var body: some View {
        VStack(spacing: 16) {
            HStack {
                Text("Policy Viewer")
                    .font(.headline)

                Spacer()

                Button("Load Policy") {
                    loadPolicy()
                }
                .disabled(isLoading)

                Button("Reload Policy") {
                    reloadPolicy()
                }
                .disabled(isLoading)
            }
            .padding()

            if let error = error {
                Text("Error: \(error)")
                    .foregroundStyle(.red)
                    .padding()
            }

            ScrollView {
                TextEditor(text: $policyContent)
                    .font(.system(.body, design: .monospaced))
                    .frame(minHeight: 200)
                    .padding()
                    .overlay(
                        RoundedRectangle(cornerRadius: 8)
                            .stroke(Color.gray.opacity(0.3), lineWidth: 1)
                    )
            }
            .padding()

            VStack(alignment: .leading, spacing: 8) {
                Text("Policy Evaluation")
                    .font(.headline)

                HStack {
                    Picker("Target Type", selection: $evalTargetType) {
                        ForEach(targetTypes, id: \.self) { type in
                            Text(type.capitalized).tag(type)
                        }
                    }
                    .frame(width: 150)

                    TextField("Target Name", text: $evalTargetName)

                    Button("Evaluate") {
                        runEvaluation()
                    }
                    .disabled(evalTargetName.isEmpty || isDryRun)
                }
            }
            .padding()

            if !dryRunResults.isEmpty {
                VStack(alignment: .leading, spacing: 8) {
                    Text("Evaluation Results")
                        .font(.headline)

                    ScrollView {
                        Text(dryRunResults)
                            .font(.system(.caption, design: .monospaced))
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding()
                            .background(Color(nsColor: .textBackgroundColor))
                            .cornerRadius(8)
                    }
                }
                .padding()
            }

            Spacer()
        }
        .navigationTitle("Policies")
        .task { loadPolicy() }
    }

    private func loadPolicy() {
        isLoading = true
        error = nil

        Task {
            let client = SidecarClient()
            do {
                let policy = try await client.policyShow()
                await MainActor.run {
                    policyContent = policy
                    isLoading = false
                }
            } catch {
                await MainActor.run {
                    self.error = error.localizedDescription
                    isLoading = false
                }
            }
        }
    }

    private func reloadPolicy() {
        isLoading = true
        error = nil

        Task {
            let client = SidecarClient()
            do {
                try await client.policyReload()
                await MainActor.run {
                    isLoading = false
                }
                // Reload the policy content after reload
                loadPolicy()
            } catch {
                await MainActor.run {
                    self.error = error.localizedDescription
                    isLoading = false
                }
            }
        }
    }

    private func runEvaluation() {
        isDryRun = true
        dryRunResults = ""
        error = nil

        Task {
            let client = SidecarClient()
            do {
                let result = try await client.policyEvaluate(targetType: evalTargetType, targetName: evalTargetName)
                await MainActor.run {
                    dryRunResults = "Verdict: \(result.verdict)\n"
                    dryRunResults += "Allowed: \(result.allow)\n"
                    if let reason = result.reason {
                        dryRunResults += "Reason: \(reason)\n"
                    }
                    if let fa = result.fileAction {
                        dryRunResults += "File Action: \(fa)\n"
                    }
                    if let ia = result.installAction {
                        dryRunResults += "Install Action: \(ia)\n"
                    }
                    isDryRun = false
                }
            } catch {
                await MainActor.run {
                    self.error = error.localizedDescription
                    dryRunResults = "Evaluation failed: \(error.localizedDescription)"
                    isDryRun = false
                }
            }
        }
    }
}
