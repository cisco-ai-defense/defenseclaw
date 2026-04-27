import Foundation
import Observation

@MainActor
@Observable
final class SetupWorkspaceModel {
    let groups = SetupCatalog.groups
    var selectedGroupID = SetupCatalog.groups.first?.id ?? "llm"
    var textValues: [String: String] = [:]
    var boolValues: [String: Bool] = [:]
    var workflowTextValues: [String: [String: String]] = [:]
    var workflowBoolValues: [String: [String: Bool]] = [:]
    var statusMessage = ""
    var commandOutput = ""
    var isLoading = false
    var isSaving = false
    var runningWorkflowID: String?

    private var originalTextValues: [String: String] = [:]
    private var originalBoolValues: [String: Bool] = [:]
    private var store = YAMLConfigStore()
    private let runner = LocalCommandRunner()

    var selectedGroup: SetupGroup {
        groups.first { $0.id == selectedGroupID } ?? groups[0]
    }

    var changedCount: Int {
        let changedText = textValues.filter { key, value in originalTextValues[key, default: ""] != value }.count
        let changedBools = boolValues.filter { key, value in originalBoolValues[key, default: false] != value }.count
        return changedText + changedBools
    }

    init() {
        seedWorkflowDefaults()
        load()
    }

    func load() {
        isLoading = true
        defer { isLoading = false }

        do {
            try store.load()
            var loadedText: [String: String] = [:]
            var loadedBool: [String: Bool] = [:]

            for field in allFields {
                switch field.kind {
                case .toggle:
                    loadedBool[field.path] = store.bool(at: field.path)
                case .password where field.secretWriteOnly:
                    loadedText[field.path] = ""
                default:
                    loadedText[field.path] = store.string(at: field.path)
                }
            }

            textValues = loadedText
            boolValues = loadedBool
            originalTextValues = loadedText
            originalBoolValues = loadedBool
            statusMessage = "Loaded \(store.url.path)"
        } catch {
            statusMessage = "Could not load config: \(error.localizedDescription)"
        }
    }

    func saveChanges() {
        isSaving = true
        defer { isSaving = false }

        do {
            try store.load()

            for field in allFields {
                switch field.kind {
                case .toggle:
                    let value = boolValues[field.path, default: false]
                    if originalBoolValues[field.path, default: false] != value {
                        store.set(value, at: field.path)
                    }
                case .integer:
                    let value = textValues[field.path, default: ""].trimmingCharacters(in: .whitespacesAndNewlines)
                    if originalTextValues[field.path, default: ""] != value {
                        if value.isEmpty {
                            store.set(nil, at: field.path)
                        } else {
                            store.set(Int(value) ?? 0, at: field.path)
                        }
                    }
                case .decimal:
                    let value = textValues[field.path, default: ""].trimmingCharacters(in: .whitespacesAndNewlines)
                    if originalTextValues[field.path, default: ""] != value {
                        if value.isEmpty {
                            store.set(nil, at: field.path)
                        } else {
                            store.set(Double(value) ?? 0, at: field.path)
                        }
                    }
                case .password where field.secretWriteOnly:
                    let value = textValues[field.path, default: ""].trimmingCharacters(in: .whitespacesAndNewlines)
                    if !value.isEmpty {
                        store.set(value, at: field.path)
                    }
                default:
                    let value = textValues[field.path, default: ""]
                    if originalTextValues[field.path, default: ""] != value {
                        store.set(value, at: field.path)
                    }
                }
            }

            try store.save()
            load()
            statusMessage = "Saved \(store.url.lastPathComponent)"
        } catch {
            statusMessage = "Save failed: \(error.localizedDescription)"
        }
    }

    func textBindingValue(for field: SetupField) -> String {
        textValues[field.path, default: ""]
    }

    func setText(_ value: String, for field: SetupField) {
        textValues[field.path] = value
    }

    func boolBindingValue(for field: SetupField) -> Bool {
        boolValues[field.path, default: false]
    }

    func setBool(_ value: Bool, for field: SetupField) {
        boolValues[field.path] = value
    }

    func workflowTextValue(_ workflow: SetupWorkflow, field: SetupWorkflowField) -> String {
        workflowTextValues[workflow.id]?[field.id] ?? field.defaultValue
    }

    func setWorkflowText(_ value: String, workflow: SetupWorkflow, field: SetupWorkflowField) {
        var values = workflowTextValues[workflow.id, default: [:]]
        values[field.id] = value
        workflowTextValues[workflow.id] = values
    }

    func workflowBoolValue(_ workflow: SetupWorkflow, field: SetupWorkflowField) -> Bool {
        workflowBoolValues[workflow.id]?[field.id] ?? parseBool(field.defaultValue)
    }

    func setWorkflowBool(_ value: Bool, workflow: SetupWorkflow, field: SetupWorkflowField) {
        var values = workflowBoolValues[workflow.id, default: [:]]
        values[field.id] = value
        workflowBoolValues[workflow.id] = values
    }

    func run(_ workflow: SetupWorkflow) {
        guard runningWorkflowID == nil else {
            return
        }

        let built = buildArguments(for: workflow)
        guard built.error == nil else {
            statusMessage = built.error ?? "Invalid workflow input"
            return
        }

        runningWorkflowID = workflow.id
        statusMessage = "Running defenseclaw \(built.arguments.joined(separator: " "))"
        commandOutput = ""

        Task {
            do {
                let result = try await runner.run("defenseclaw", arguments: built.arguments)
                await MainActor.run {
                    commandOutput = format(result)
                    statusMessage = result.exitCode == 0 ? "\(workflow.title) finished" : "\(workflow.title) failed with exit \(result.exitCode)"
                    runningWorkflowID = nil
                    load()
                }
            } catch {
                await MainActor.run {
                    commandOutput = error.localizedDescription
                    statusMessage = "\(workflow.title) could not start"
                    runningWorkflowID = nil
                }
            }
        }
    }

    func commandPreview(for workflow: SetupWorkflow) -> String {
        "defenseclaw " + buildArguments(for: workflow).arguments.joined(separator: " ")
    }

    private var allFields: [SetupField] {
        groups.flatMap(\.fields)
    }

    private func seedWorkflowDefaults() {
        for workflow in groups.flatMap(\.workflows) {
            var text: [String: String] = [:]
            var bools: [String: Bool] = [:]

            for field in workflow.fields {
                switch field.kind {
                case .toggle:
                    bools[field.id] = parseBool(field.defaultValue)
                default:
                    text[field.id] = field.defaultValue
                }
            }

            workflowTextValues[workflow.id] = text
            workflowBoolValues[workflow.id] = bools
        }
    }

    private func buildArguments(for workflow: SetupWorkflow) -> (arguments: [String], error: String?) {
        var args = workflow.command

        for field in workflow.fields {
            switch field.kind {
            case .toggle:
                let value = workflowBoolValue(workflow, field: field)
                if value {
                    args.append(field.flag)
                } else if let noFlag = field.noFlag, field.alwaysPass {
                    args.append(noFlag)
                } else if let noFlag = field.noFlag,
                          parseBool(field.defaultValue) != value {
                    args.append(noFlag)
                }
            default:
                let value = workflowTextValue(workflow, field: field).trimmingCharacters(in: .whitespacesAndNewlines)
                if field.required && value.isEmpty {
                    return (args, "\(workflow.title) requires \(field.label)")
                }
                if field.secret && value.isEmpty {
                    continue
                }
                guard !field.flag.isEmpty else {
                    continue
                }
                if field.alwaysPass || field.required || (!value.isEmpty && value != field.defaultValue) {
                    args.append(field.flag)
                    args.append(value)
                }
            }
        }

        return (args, nil)
    }

    private func format(_ result: LocalCommandResult) -> String {
        let output = result.combinedOutput
        let body = output.isEmpty ? "(no output)" : output
        return """
        $ \(result.commandLine)
        exit \(result.exitCode)

        \(body)
        """
    }

    private func parseBool(_ value: String) -> Bool {
        ["true", "yes", "1", "on"].contains(value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased())
    }
}
