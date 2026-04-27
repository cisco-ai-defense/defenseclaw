import SwiftUI
import DefenseClawKit

struct PolicyView: View {
    @State private var model = TextFileEditorModel(mode: .policy)
    @State private var evalTargetType = "skill"
    @State private var evalTargetName = ""
    @State private var evalSeverity = "MEDIUM"
    @State private var evalFindings = 0
    @State private var evaluationResult = ""
    @State private var reloadMessage = ""
    @State private var isEvaluating = false
    @State private var isReloading = false

    private let targetTypes = ["skill", "mcp", "plugin", "tool"]
    private let severityLevels = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    private let sidecarClient = SidecarClient()

    var body: some View {
        ManagedTextFileWorkspaceView(
            model: model,
            title: "Policy Editor",
            subtitle: "Edit admission, guardrail, scanner, firewall, sandbox, and Rego policy files without leaving the app.",
            emptyMessage: "No policy files found"
        ) {
            policyControls
        }
        .navigationTitle("Policy")
    }

    private var policyControls: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 12) {
                Button {
                    reloadRuntimePolicy()
                } label: {
                    Label("Reload Runtime Policy", systemImage: "arrow.triangle.2.circlepath")
                }
                .disabled(isReloading)

                if isReloading {
                    ProgressView()
                        .controlSize(.small)
                }

                Text(reloadMessage)
                    .font(.caption)
                    .foregroundStyle(reloadMessage.lowercased().contains("failed") ? .red : .secondary)
                    .lineLimit(1)

                Spacer()
            }

            VStack(alignment: .leading, spacing: 10) {
                Text("Evaluate Current Policy")
                    .font(.subheadline.weight(.semibold))

                HStack(spacing: 10) {
                    Picker("Target", selection: $evalTargetType) {
                        ForEach(targetTypes, id: \.self) { type in
                            Text(type.capitalized).tag(type)
                        }
                    }
                    .pickerStyle(.segmented)
                    .frame(width: 260)

                    TextField("Target name or path", text: $evalTargetName)
                        .textFieldStyle(.roundedBorder)
                        .frame(minWidth: 220)
                        .layoutPriority(1)
                }

                HStack(spacing: 10) {
                    Picker("Severity", selection: $evalSeverity) {
                        ForEach(severityLevels, id: \.self) { severity in
                            Text(severity).tag(severity)
                        }
                    }
                    .frame(width: 150)

                    Stepper("Findings \(evalFindings)", value: $evalFindings, in: 0...100)
                        .frame(width: 150)

                    Button {
                        runEvaluation()
                    } label: {
                        Label("Evaluate", systemImage: "play.circle")
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(evalTargetName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || isEvaluating)

                    if isEvaluating {
                        ProgressView()
                            .controlSize(.small)
                    }

                    Spacer()
                }

                if !evaluationResult.isEmpty {
                    Text(evaluationResult)
                        .font(.caption.monospaced())
                        .foregroundStyle(.secondary)
                        .lineLimit(5)
                        .padding(10)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 8))
                }
            }
        }
    }

    private func reloadRuntimePolicy() {
        isReloading = true
        reloadMessage = ""

        Task {
            do {
                try await sidecarClient.policyReload()
                await MainActor.run {
                    reloadMessage = "Runtime policy reloaded"
                    isReloading = false
                }
            } catch {
                await MainActor.run {
                    reloadMessage = "Reload failed: \(error.localizedDescription)"
                    isReloading = false
                }
            }
        }
    }

    private func runEvaluation() {
        let targetName = evalTargetName.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !targetName.isEmpty else {
            return
        }

        isEvaluating = true
        evaluationResult = ""

        Task {
            let input = AdmissionInput(
                targetType: evalTargetType,
                targetName: targetName,
                severity: evalSeverity,
                findings: evalFindings
            )

            do {
                let result = try await sidecarClient.policyEvaluate(input: input)
                await MainActor.run {
                    evaluationResult = format(result)
                    isEvaluating = false
                }
            } catch {
                await MainActor.run {
                    evaluationResult = "Evaluation failed: \(error.localizedDescription)"
                    isEvaluating = false
                }
            }
        }
    }

    private func format(_ result: AdmissionOutput) -> String {
        var lines = [
            "Verdict: \(result.verdict)",
            "Allowed: \(result.allow ? "yes" : "no")"
        ]

        if let reason = result.reason, !reason.isEmpty {
            lines.append("Reason: \(reason)")
        }
        if let fileAction = result.fileAction, !fileAction.isEmpty {
            lines.append("File action: \(fileAction)")
        }
        if let installAction = result.installAction, !installAction.isEmpty {
            lines.append("Install action: \(installAction)")
        }

        return lines.joined(separator: "\n")
    }
}
