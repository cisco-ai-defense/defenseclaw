import SwiftUI
import DefenseClawKit

struct PolicyView: View {
    @State private var policyContent = ""
    @State private var isLoading = false
    @State private var isDryRun = false
    @State private var dryRunResults = ""
    @State private var error: String?

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

                Button("Dry Run") {
                    runDryRun()
                }
                .disabled(policyContent.isEmpty || isDryRun)
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

            if !dryRunResults.isEmpty {
                VStack(alignment: .leading, spacing: 8) {
                    Text("Dry Run Results")
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

    private func runDryRun() {
        isDryRun = true
        dryRunResults = ""

        Task {
            let client = SidecarClient()
            do {
                // Note: There's no dry run endpoint in the actual API,
                // so we'll just do a basic policy evaluate
                let result = try await client.policyEvaluate(targetType: "skill", targetName: "test")
                await MainActor.run {
                    dryRunResults = "Policy evaluation result: \(result.verdict)\n"
                    dryRunResults += "Allow: \(result.allow)\n"
                    if let reason = result.reason {
                        dryRunResults += "Reason: \(reason)\n"
                    }
                    isDryRun = false
                }
            } catch {
                await MainActor.run {
                    self.error = error.localizedDescription
                    dryRunResults = "Dry run failed: \(error.localizedDescription)"
                    isDryRun = false
                }
            }
        }
    }
}
