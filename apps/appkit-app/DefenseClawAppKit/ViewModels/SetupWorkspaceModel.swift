import Foundation
import Observation

@MainActor
@Observable
final class SetupWorkspaceModel {
    static let hubGroupID = "hub"

    let groups = SetupCatalog.groups
    var selectedGroupID = SetupWorkspaceModel.qaDefaultGroupID
    var textValues: [String: String] = [:]
    var boolValues: [String: Bool] = [:]
    var workflowTextValues: [String: [String: String]] = [:]
    var workflowBoolValues: [String: [String: Bool]] = [:]
    var statusMessage = ""
    var commandOutput = ""
    var lastTaskResult: SetupTaskResult?
    var isLoading = false
    var isSaving = false
    var runningWorkflowID: String?

    private var originalTextValues: [String: String] = [:]
    private var originalBoolValues: [String: Bool] = [:]
    private var store = YAMLConfigStore()
    private let runner = LocalCommandRunner()

    private static var qaDefaultGroupID: String {
        let arguments = ProcessInfo.processInfo.arguments

        if let index = arguments.firstIndex(of: "--qa-setup-group"),
           arguments.indices.contains(index + 1),
           SetupCatalog.groups.contains(where: { $0.id == arguments[index + 1] }) {
            return arguments[index + 1]
        }

        if let argument = arguments.first(where: { $0.hasPrefix("--qa-setup-group=") }) {
            let groupID = String(argument.dropFirst("--qa-setup-group=".count))
            if SetupCatalog.groups.contains(where: { $0.id == groupID }) {
                return groupID
            }
        }

        return hubGroupID
    }

    var selectedGroup: SetupGroup {
        groups.first { $0.id == selectedGroupID } ?? groups[0]
    }

    var isHubSelected: Bool {
        selectedGroupID == Self.hubGroupID
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
        statusMessage = "Running \(workflow.title)"
        commandOutput = ""
        lastTaskResult = nil

        Task {
            do {
                let result = try await runner.run("defenseclaw", arguments: built.arguments)
                await MainActor.run {
                    commandOutput = format(result)
                    lastTaskResult = SetupTaskResult(workflowTitle: workflow.title, result: result)
                    statusMessage = result.exitCode == 0 ? "\(workflow.title) finished" : "\(workflow.title) failed with exit \(result.exitCode)"
                    runningWorkflowID = nil
                    load()
                }
            } catch {
                await MainActor.run {
                    commandOutput = error.localizedDescription
                    lastTaskResult = SetupTaskResult(workflowTitle: workflow.title, startError: error)
                    statusMessage = "\(workflow.title) could not start"
                    runningWorkflowID = nil
                }
            }
        }
    }

    func commandPreview(for workflow: SetupWorkflow) -> String {
        "defenseclaw " + buildArguments(for: workflow).arguments.joined(separator: " ")
    }

    func visibleGroups(includeAdvanced: Bool) -> [SetupGroup] {
        includeAdvanced ? groups : groups.filter { !$0.isAdvanced }
    }

    func selectGroup(_ groupID: String) {
        selectedGroupID = groupID
    }

    func group(withID groupID: String) -> SetupGroup? {
        groups.first { $0.id == groupID }
    }

    func workflow(withID workflowID: String) -> SetupWorkflow? {
        groups.flatMap(\.workflows).first { $0.id == workflowID }
    }

    func primaryFields(for group: SetupGroup) -> [SetupField] {
        let primaryPaths = Self.primaryFieldPaths[group.id, default: []]
        return group.fields.filter { primaryPaths.contains($0.path) }
    }

    func advancedFields(for group: SetupGroup) -> [SetupField] {
        let primaryPaths = Self.primaryFieldPaths[group.id, default: []]
        return group.fields.filter { !primaryPaths.contains($0.path) }
    }

    func visibleWorkflows(for group: SetupGroup, includeAdvanced: Bool) -> [SetupWorkflow] {
        if includeAdvanced {
            return group.workflows
        }
        return group.workflows.filter { !Self.advancedWorkflowIDs.contains($0.id) }
    }

    func hiddenWorkflowCount(for group: SetupGroup, includeAdvanced: Bool) -> Int {
        includeAdvanced ? 0 : group.workflows.count - visibleWorkflows(for: group, includeAdvanced: false).count
    }

    func visibleWorkflowFields(
        for workflow: SetupWorkflow,
        includeAdvanced: Bool
    ) -> [SetupWorkflowField] {
        if includeAdvanced {
            return workflow.fields
        }

        return workflow.fields.filter { field in
            isPrimaryWorkflowField(field, workflow: workflow)
        }
    }

    func hiddenWorkflowFieldCount(for workflow: SetupWorkflow, includeAdvanced: Bool) -> Int {
        includeAdvanced ? 0 : workflow.fields.count - visibleWorkflowFields(for: workflow, includeAdvanced: false).count
    }

    private var allFields: [SetupField] {
        groups.flatMap(\.fields)
    }

    private static let primaryFieldPaths: [String: Set<String>] = [
        "llm": [
            "llm.provider",
            "llm.model",
            "llm.api_key_env",
            "llm.api_key",
            "claw.mode"
        ],
        "gateway": [
            "gateway.watcher.enabled",
            "gateway.watcher.skill.enabled",
            "gateway.watcher.skill.take_action",
            "gateway.watcher.plugin.enabled",
            "gateway.watcher.plugin.take_action",
            "gateway.watcher.mcp.take_action",
            "gateway.auto_approve_safe"
        ],
        "scanners": [
            "scanners.skill_scanner.policy",
            "scanners.skill_scanner.lenient",
            "scanners.skill_scanner.use_llm",
            "scanners.skill_scanner.use_behavioral",
            "scanners.skill_scanner.use_virustotal",
            "scanners.skill_scanner.use_aidefense",
            "scanners.mcp_scanner.scan_prompts",
            "scanners.mcp_scanner.scan_resources",
            "scanners.mcp_scanner.scan_instructions"
        ],
        "guardrail": [
            "guardrail.enabled",
            "guardrail.mode",
            "guardrail.scanner_mode",
            "guardrail.block_message",
            "guardrail.judge.enabled",
            "guardrail.judge.injection",
            "guardrail.judge.pii"
        ],
        "observability": [
            "otel.enabled",
            "otel.endpoint",
            "otel.protocol",
            "otel.traces.enabled",
            "otel.logs.enabled",
            "otel.metrics.enabled"
        ],
        "enforcement": [
            "watch.auto_block",
            "watch.allow_list_bypass_scan",
            "watch.rescan_enabled"
        ],
        "sandbox": [
            "openshell.mode",
            "openshell.policy_dir",
            "openshell.host_networking"
        ]
    ]

    private static let advancedWorkflowIDs: Set<String> = [
        "observability-list",
        "observability-migrate-splunk"
    ]

    private static let primaryWorkflowFieldIDs: [String: Set<String>] = [
        "gateway-setup": ["--remote", "--verify"],
        "skill-scanner": [
            "--policy",
            "--use-behavioral",
            "--use-llm",
            "--use-virustotal",
            "--use-aidefense",
            "--verify"
        ],
        "mcp-scanner": [
            "--scan-prompts",
            "--scan-resources",
            "--scan-instructions",
            "--verify"
        ],
        "guardrail-setup": [
            "--mode",
            "--scanner-mode",
            "--provider",
            "--model",
            "--api-key-env",
            "--judge",
            "--verify"
        ],
        "sandbox-setup": [
            "--policy",
            "--disable"
        ]
    ]

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

    private func isPrimaryWorkflowField(_ field: SetupWorkflowField, workflow: SetupWorkflow) -> Bool {
        if workflow.id == "gateway-setup",
           ["--host", "--port", "--api-port", "--token"].contains(field.flag),
           workflowBoolValue(workflow, field: SetupWorkflowField("Remote Mode", flag: "--remote", kind: .toggle)) {
            return true
        }

        if let explicit = Self.primaryWorkflowFieldIDs[workflow.id] {
            return explicit.contains(field.id)
        }

        if field.required || field.secret {
            return true
        }

        let coreFlags: Set<String> = [
            "--enabled",
            "--signals",
            "--site",
            "--realm",
            "--host",
            "--port",
            "--index",
            "--source",
            "--sourcetype",
            "--endpoint",
            "--protocol",
            "--target",
            "--url",
            "--method",
            "--verify-tls",
            "--min-severity",
            "--secret-env",
            "--room-id"
        ]
        return coreFlags.contains(field.flag)
    }
}

enum SetupTaskState: String {
    case passed = "PASS"
    case warning = "WARN"
    case failed = "FAIL"
    case skipped = "SKIP"

    var label: String {
        switch self {
        case .passed: return "Passed"
        case .warning: return "Warning"
        case .failed: return "Failed"
        case .skipped: return "Skipped"
        }
    }
}

struct SetupTaskCheck: Identifiable, Hashable {
    let id = UUID()
    let state: SetupTaskState
    let message: String
}

struct SetupTaskResult: Identifiable, Hashable {
    let id = UUID()
    let workflowTitle: String
    let commandLine: String
    let exitCode: Int
    let rawOutput: String
    let checks: [SetupTaskCheck]
    let startError: String?

    init(workflowTitle: String, result: LocalCommandResult) {
        self.workflowTitle = workflowTitle
        self.commandLine = result.commandLine
        self.exitCode = Int(result.exitCode)
        self.rawOutput = result.combinedOutput
        self.checks = Self.parseChecks(result.combinedOutput)
        self.startError = nil
    }

    init(workflowTitle: String, startError error: Error) {
        self.workflowTitle = workflowTitle
        self.commandLine = ""
        self.exitCode = -1
        self.rawOutput = error.localizedDescription
        self.checks = []
        self.startError = error.localizedDescription
    }

    var succeeded: Bool {
        exitCode == 0 && startError == nil
    }

    var headline: String {
        if let startError {
            return "Could not start: \(startError)"
        }
        if succeeded {
            return "\(workflowTitle) completed"
        }
        return "\(workflowTitle) needs attention"
    }

    var summary: String {
        if checks.isEmpty {
            return succeeded ? "No issues were reported." : "Review the technical output for details."
        }

        let failed = count(.failed)
        let warnings = count(.warning)
        let skipped = count(.skipped)
        let passed = count(.passed)

        var parts: [String] = []
        if failed > 0 { parts.append("\(failed) failed") }
        if warnings > 0 { parts.append("\(warnings) warnings") }
        if skipped > 0 { parts.append("\(skipped) skipped") }
        if passed > 0 { parts.append("\(passed) passed") }
        return parts.joined(separator: ", ")
    }

    var prioritizedChecks: [SetupTaskCheck] {
        checks.sorted { left, right in
            Self.rank(left.state) < Self.rank(right.state)
        }
    }

    func count(_ state: SetupTaskState) -> Int {
        checks.filter { $0.state == state }.count
    }

    private static func parseChecks(_ output: String) -> [SetupTaskCheck] {
        output
            .split(separator: "\n")
            .compactMap { line -> SetupTaskCheck? in
                let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
                let states: [(String, SetupTaskState)] = [
                    ("[FAIL]", .failed),
                    ("[WARN]", .warning),
                    ("[PASS]", .passed),
                    ("[SKIP]", .skipped)
                ]

                guard let match = states.first(where: { trimmed.hasPrefix($0.0) }) else {
                    return nil
                }

                let message = trimmed
                    .dropFirst(match.0.count)
                    .trimmingCharacters(in: CharacterSet(charactersIn: " \t-"))
                return SetupTaskCheck(state: match.1, message: message.isEmpty ? match.1.label : message)
            }
    }

    private static func rank(_ state: SetupTaskState) -> Int {
        switch state {
        case .failed: return 0
        case .warning: return 1
        case .skipped: return 2
        case .passed: return 3
        }
    }
}
