import SwiftUI

struct SetupView: View {
    @State private var model = SetupWorkspaceModel()
    @State private var showAdvanced = false

    private var selection: Binding<String?> {
        Binding(
            get: { model.selectedGroupID },
            set: { newValue in
                if let newValue {
                    model.selectedGroupID = newValue
                }
            }
        )
    }

    var body: some View {
        HSplitView {
            sidebar
                .frame(minWidth: 220, idealWidth: 250, maxWidth: 300)

            detail
                .frame(minWidth: 560)
        }
        .background(Color(nsColor: .windowBackgroundColor))
        .navigationTitle("Setup")
        .onChange(of: showAdvanced) { _, includeAdvanced in
            if !includeAdvanced,
               let group = model.group(withID: model.selectedGroupID),
               group.isAdvanced {
                model.selectGroup(SetupWorkspaceModel.hubGroupID)
            }
        }
    }

    private var sidebar: some View {
        VStack(alignment: .leading, spacing: 14) {
            VStack(alignment: .leading, spacing: 4) {
                Text("Setup")
                    .font(.title3.weight(.semibold))
                Text("Guided setup for protection, scanners, integrations, and runtime services.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            List(selection: selection) {
                Section("Start") {
                    Label("Overview", systemImage: "checklist")
                        .tag(Optional(SetupWorkspaceModel.hubGroupID))
                }
                ForEach(model.groups) { group in
                    if model.visibleGroups(includeAdvanced: showAdvanced).contains(group) {
                        SetupSidebarRow(group: group)
                            .tag(Optional(group.id))
                    }
                }
            }
            .listStyle(.sidebar)

            VStack(alignment: .leading, spacing: 6) {
                HStack(spacing: 8) {
                    Label("\(model.changedCount) unsaved", systemImage: "pencil.line")
                    Spacer()
                    if model.isLoading || model.isSaving {
                        ProgressView()
                            .controlSize(.small)
                    }
                }
                .font(.caption)
                .foregroundStyle(.secondary)

                Text(model.statusMessage)
                    .font(.caption)
                    .foregroundStyle(model.statusMessage.localizedCaseInsensitiveContains("failed") ? .red : .secondary)
                    .lineLimit(3)
            }
        }
        .padding(18)
    }

    private var detail: some View {
        VStack(spacing: 0) {
            detailToolbar

            Divider()

            if model.isHubSelected {
                SetupHubView(model: model, showAdvanced: $showAdvanced)
            } else {
                groupDetail
            }
        }
    }

    private var detailToolbar: some View {
        HStack(spacing: 12) {
            Label(model.isHubSelected ? "Guided Setup" : model.selectedGroup.title,
                  systemImage: model.isHubSelected ? "checklist" : model.selectedGroup.systemImage)
                .font(.title2.weight(.semibold))
            Spacer()
            Toggle(isOn: $showAdvanced) {
                Label("Advanced", systemImage: "slider.horizontal.3")
            }
            .toggleStyle(.button)
            .controlSize(.small)
            Button {
                model.load()
            } label: {
                Label("Reload", systemImage: "arrow.clockwise")
            }
            Button {
                model.saveChanges()
            } label: {
                Label("Save", systemImage: "square.and.arrow.down")
            }
            .buttonStyle(.borderedProminent)
            .disabled(model.changedCount == 0 || model.isSaving)
        }
        .padding(18)
    }

    private var groupDetail: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                Text(model.selectedGroup.subtitle)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)

                if !model.selectedGroup.fields.isEmpty {
                    SetupFieldSection(model: model, group: model.selectedGroup, showAdvanced: showAdvanced)
                }

                let visibleWorkflows = model.visibleWorkflows(for: model.selectedGroup, includeAdvanced: showAdvanced)
                if !visibleWorkflows.isEmpty {
                    SetupWorkflowSection(
                        model: model,
                        group: model.selectedGroup,
                        workflows: visibleWorkflows,
                        showAdvanced: showAdvanced
                    )
                }

                if let result = model.lastTaskResult {
                    SetupTaskResultView(result: result)
                }
            }
            .padding(18)
        }
    }
}

private struct SetupHubView: View {
    @Bindable var model: SetupWorkspaceModel
    @Binding var showAdvanced: Bool

    private let primarySteps: [SetupHubStep] = [
        SetupHubStep(
            title: "1. Add LLM and agent basics",
            subtitle: "Provider, model, DefenseClaw LLM key reference, and coding-agent discovery.",
            systemImage: "brain.head.profile",
            tint: .blue,
            groupID: "llm",
            workflowID: "doctor"
        ),
        SetupHubStep(
            title: "2. Connect the local gateway",
            subtitle: "Configure the helper, API bind, watchers, and OpenClaw connection.",
            systemImage: "network",
            tint: .teal,
            groupID: "gateway",
            workflowID: "gateway-setup"
        ),
        SetupHubStep(
            title: "3. Enable scanner coverage",
            subtitle: "Prepare skill and MCP scanners before trusting scan counts.",
            systemImage: "magnifyingglass",
            tint: .purple,
            groupID: "scanners",
            workflowID: "skill-scanner"
        ),
        SetupHubStep(
            title: "4. Turn on guardrails",
            subtitle: "Start in observe mode, choose local or remote scanning, then verify.",
            systemImage: "shield",
            tint: .green,
            groupID: "guardrail",
            workflowID: "guardrail-setup"
        )
    ]

    private let optionalSteps: [SetupHubStep] = [
        SetupHubStep(
            title: "Observability",
            subtitle: "Splunk, Datadog, Honeycomb, New Relic, Grafana, or generic OTLP.",
            systemImage: "waveform.path.ecg",
            tint: .orange,
            groupID: "observability",
            workflowID: "obs-splunk-o11y"
        ),
        SetupHubStep(
            title: "Webhooks",
            subtitle: "Slack, PagerDuty, Webex, and generic HMAC notifications.",
            systemImage: "bell.and.waves.left.and.right",
            tint: .indigo,
            groupID: "webhooks",
            workflowID: "webhook-slack"
        ),
        SetupHubStep(
            title: "Enforcement defaults",
            subtitle: "Severity matrices for skill, MCP, and plugin admission.",
            systemImage: "lock.shield",
            tint: .red,
            groupID: "enforcement",
            workflowID: nil
        ),
        SetupHubStep(
            title: "Sandbox",
            subtitle: "OpenShell policy setup. Runtime execution remains Linux-only.",
            systemImage: "shippingbox",
            tint: .brown,
            groupID: "sandbox",
            workflowID: "sandbox-setup"
        )
    ]

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                hero
                stepSection("Essentials", steps: primarySteps)
                optionalSection

                if let result = model.lastTaskResult {
                    SetupTaskResultView(result: result)
                }
            }
            .padding(18)
        }
    }

    private var hero: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Start with the essentials, then add integrations when you need them.")
                .font(.title3.weight(.semibold))
            Text("This hub keeps first-time setup focused. Every config field still exists, but advanced groups are hidden until you enable Advanced.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            HStack(spacing: 10) {
                Button {
                    if let doctor = model.workflow(withID: "doctor") {
                        model.run(doctor)
                    }
                } label: {
                    Label("Run Doctor", systemImage: "stethoscope")
                }
                .buttonStyle(.borderedProminent)
                .disabled(model.runningWorkflowID != nil)

                Button {
                    (NSApp.delegate as? AppDelegate)?.showPolicy()
                } label: {
                    Label("Open Policy Editor", systemImage: "doc.text.magnifyingglass")
                }

                Button {
                    showAdvanced.toggle()
                } label: {
                    Label(showAdvanced ? "Hide Advanced" : "Show Advanced", systemImage: "slider.horizontal.3")
                }
            }
        }
        .padding(18)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 10))
        .overlay(
            RoundedRectangle(cornerRadius: 10)
                .stroke(Color(nsColor: .separatorColor).opacity(0.55), lineWidth: 0.5)
        )
    }

    private func stepSection(_ title: String, steps: [SetupHubStep]) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(title)
                .font(.headline)
            LazyVGrid(columns: [GridItem(.adaptive(minimum: 280), spacing: 12)], spacing: 12) {
                ForEach(steps) { step in
                    SetupHubStepCard(model: model, step: step, showAdvanced: $showAdvanced)
                }
            }
        }
    }

    private var optionalSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("Optional and Advanced")
                    .font(.headline)
                Spacer()
                if !showAdvanced {
                    Text("Hidden in normal mode")
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(.secondary)
                }
            }

            if showAdvanced {
                LazyVGrid(columns: [GridItem(.adaptive(minimum: 280), spacing: 12)], spacing: 12) {
                    ForEach(optionalSteps) { step in
                        SetupHubStepCard(model: model, step: step, showAdvanced: $showAdvanced)
                    }
                }
            } else {
                SetupHiddenAdvancedNotice(
                    count: optionalSteps.count,
                    label: "optional setup areas hidden until Advanced is enabled"
                )
            }
        }
    }
}

private struct SetupHubStep: Identifiable {
    let id = UUID()
    let title: String
    let subtitle: String
    let systemImage: String
    let tint: Color
    let groupID: String
    let workflowID: String?
}

private struct SetupHubStepCard: View {
    @Bindable var model: SetupWorkspaceModel
    let step: SetupHubStep
    @Binding var showAdvanced: Bool

    private var workflow: SetupWorkflow? {
        step.workflowID.flatMap { model.workflow(withID: $0) }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .top, spacing: 10) {
                Image(systemName: step.systemImage)
                    .foregroundStyle(step.tint)
                    .frame(width: 20)

                VStack(alignment: .leading, spacing: 4) {
                    Text(step.title)
                        .font(.headline)
                    Text(step.subtitle)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }

                Spacer(minLength: 0)
            }

            HStack {
                Button {
                    showAdvanced = showAdvanced || (model.group(withID: step.groupID)?.isAdvanced == true)
                    model.selectGroup(step.groupID)
                } label: {
                    Label("Configure", systemImage: "slider.horizontal.3")
                }

                if let workflow {
                    Button {
                        model.run(workflow)
                    } label: {
                        Label(model.runningWorkflowID == workflow.id ? "Running" : "Run", systemImage: "play.fill")
                    }
                    .disabled(model.runningWorkflowID != nil)
                }
            }
            .controlSize(.small)
        }
        .padding(14)
        .frame(maxWidth: .infinity, minHeight: 150, alignment: .topLeading)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 8))
        .overlay(
            RoundedRectangle(cornerRadius: 8)
                .stroke(Color(nsColor: .separatorColor).opacity(0.55), lineWidth: 0.5)
        )
    }
}

private struct SetupSidebarRow: View {
    let group: SetupGroup

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: group.systemImage)
                .foregroundStyle(.secondary)
                .frame(width: 18)

            VStack(alignment: .leading, spacing: 2) {
                Text(group.title)
                    .lineLimit(1)
                Text(group.subtitle)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
        }
        .padding(.vertical, 2)
    }
}

private struct SetupFieldSection: View {
    @Bindable var model: SetupWorkspaceModel
    let group: SetupGroup
    let showAdvanced: Bool

    private var primaryFields: [SetupField] {
        model.primaryFields(for: group)
    }

    private var advancedFields: [SetupField] {
        model.advancedFields(for: group)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            if !primaryFields.isEmpty {
                VStack(alignment: .leading, spacing: 12) {
                    Label("Recommended Settings", systemImage: "checkmark.seal")
                        .font(.headline)

                    fieldGrid(primaryFields, showPath: false)
                }
            }

            if !advancedFields.isEmpty {
                if showAdvanced {
                    VStack(alignment: .leading, spacing: 12) {
                        Label("Advanced Settings", systemImage: "wrench.and.screwdriver")
                            .font(.headline)

                        fieldGrid(advancedFields, showPath: true)
                    }
                } else {
                    SetupHiddenAdvancedNotice(
                        count: advancedFields.count,
                        label: "advanced settings hidden in normal mode"
                    )
                }
            }
        }
    }

    private func fieldGrid(_ fields: [SetupField], showPath: Bool) -> some View {
        LazyVGrid(columns: [GridItem(.adaptive(minimum: 270), spacing: 12)], spacing: 12) {
            ForEach(fields) { field in
                SetupFieldCard(model: model, field: field, showPath: showPath)
            }
        }
    }
}

private struct SetupFieldCard: View {
    @Bindable var model: SetupWorkspaceModel
    let field: SetupField
    let showPath: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text(field.label)
                    .font(.subheadline.weight(.semibold))
                    .lineLimit(1)
                Spacer()
                if showPath {
                    Text(field.path)
                        .font(.caption2.monospaced())
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
            }

            control

            if !field.help.isEmpty {
                Text(field.help)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 8))
        .overlay(
            RoundedRectangle(cornerRadius: 8)
                .stroke(Color(nsColor: .separatorColor), lineWidth: 1)
        )
    }

    @ViewBuilder
    private var control: some View {
        switch field.kind {
        case .toggle:
            Toggle("", isOn: Binding(
                get: { model.boolBindingValue(for: field) },
                set: { model.setBool($0, for: field) }
            ))
            .labelsHidden()
        case .choice:
            Picker("", selection: Binding(
                get: { model.textBindingValue(for: field) },
                set: { model.setText($0, for: field) }
            )) {
                ForEach(field.options, id: \.self) { option in
                    Text(option.isEmpty ? "Inherit" : option).tag(option)
                }
            }
            .labelsHidden()
            .pickerStyle(.menu)
        case .password:
            SecureField(field.placeholder, text: Binding(
                get: { model.textBindingValue(for: field) },
                set: { model.setText($0, for: field) }
            ))
            .textFieldStyle(.roundedBorder)
        default:
            TextField(field.placeholder, text: Binding(
                get: { model.textBindingValue(for: field) },
                set: { model.setText($0, for: field) }
            ))
            .textFieldStyle(.roundedBorder)
        }
    }
}

private struct SetupWorkflowSection: View {
    @Bindable var model: SetupWorkspaceModel
    let group: SetupGroup
    let workflows: [SetupWorkflow]
    let showAdvanced: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label("Setup Actions", systemImage: "play.circle")
                .font(.headline)

            ForEach(workflows) { workflow in
                SetupWorkflowCard(model: model, workflow: workflow, showAdvanced: showAdvanced)
            }

            let hidden = model.hiddenWorkflowCount(for: group, includeAdvanced: showAdvanced)
            if hidden > 0 {
                SetupHiddenAdvancedNotice(
                    count: hidden,
                    label: "support workflows hidden in normal mode"
                )
            }
        }
    }
}

private struct SetupWorkflowCard: View {
    @Bindable var model: SetupWorkspaceModel
    let workflow: SetupWorkflow
    let showAdvanced: Bool

    private var isRunning: Bool {
        model.runningWorkflowID == workflow.id
    }

    private var visibleFields: [SetupWorkflowField] {
        model.visibleWorkflowFields(for: workflow, includeAdvanced: showAdvanced)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .top, spacing: 12) {
                VStack(alignment: .leading, spacing: 3) {
                    Text(workflow.title)
                        .font(.headline)
                    Text(workflow.subtitle)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }

                Spacer()

                Button {
                    model.run(workflow)
                } label: {
                    if isRunning {
                        Label("Running", systemImage: "hourglass")
                    } else {
                        Label("Run", systemImage: "play.fill")
                    }
                }
                .buttonStyle(.borderedProminent)
                .disabled(model.runningWorkflowID != nil)
            }

            if !visibleFields.isEmpty {
                LazyVGrid(columns: [GridItem(.adaptive(minimum: 220), spacing: 10)], spacing: 10) {
                    ForEach(visibleFields) { field in
                        workflowField(field)
                    }
                }
            }

            let hidden = model.hiddenWorkflowFieldCount(for: workflow, includeAdvanced: showAdvanced)
            if hidden > 0 {
                SetupHiddenAdvancedNotice(
                    count: hidden,
                    label: "advanced workflow options hidden in normal mode"
                )
            }

            if showAdvanced {
                Text(model.commandPreview(for: workflow))
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
                    .truncationMode(.middle)
            }
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 8))
        .overlay(
            RoundedRectangle(cornerRadius: 8)
                .stroke(Color(nsColor: .separatorColor), lineWidth: 1)
        )
    }

    @ViewBuilder
    private func workflowField(_ field: SetupWorkflowField) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(field.label)
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)
                .lineLimit(1)

            switch field.kind {
            case .toggle:
                Toggle("", isOn: Binding(
                    get: { model.workflowBoolValue(workflow, field: field) },
                    set: { model.setWorkflowBool($0, workflow: workflow, field: field) }
                ))
                .labelsHidden()
            case .choice:
                Picker("", selection: Binding(
                    get: { model.workflowTextValue(workflow, field: field) },
                    set: { model.setWorkflowText($0, workflow: workflow, field: field) }
                )) {
                    ForEach(field.options, id: \.self) { option in
                        Text(option).tag(option)
                    }
                }
                .labelsHidden()
                .pickerStyle(.menu)
            case .password:
                SecureField("", text: Binding(
                    get: { model.workflowTextValue(workflow, field: field) },
                    set: { model.setWorkflowText($0, workflow: workflow, field: field) }
                ))
                .textFieldStyle(.roundedBorder)
            default:
                TextField("", text: Binding(
                    get: { model.workflowTextValue(workflow, field: field) },
                    set: { model.setWorkflowText($0, workflow: workflow, field: field) }
                ))
                .textFieldStyle(.roundedBorder)
            }
        }
    }
}

private struct SetupHiddenAdvancedNotice: View {
    let count: Int
    let label: String

    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: "sparkles")
                .foregroundStyle(.blue)
            Text("\(count) \(label).")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 8)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.blue.opacity(0.08), in: RoundedRectangle(cornerRadius: 8))
    }
}

private struct SetupTaskResultView: View {
    let result: SetupTaskResult
    @State private var showTechnicalOutput = false

    private var tint: Color {
        result.succeeded ? .green : .orange
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label("Last Run", systemImage: result.succeeded ? "checkmark.circle" : "exclamationmark.triangle")
                .font(.headline)
                .foregroundStyle(tint)

            VStack(alignment: .leading, spacing: 12) {
                HStack(alignment: .top, spacing: 10) {
                    Image(systemName: result.succeeded ? "checkmark.seal.fill" : "exclamationmark.triangle.fill")
                        .foregroundStyle(tint)
                    VStack(alignment: .leading, spacing: 4) {
                        Text(result.headline)
                            .font(.headline)
                        Text(result.summary)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                }

                if !result.prioritizedChecks.isEmpty {
                    VStack(spacing: 6) {
                        ForEach(result.prioritizedChecks.prefix(10)) { check in
                            SetupTaskCheckRow(check: check)
                        }

                        if result.prioritizedChecks.count > 10 {
                            Text("\(result.prioritizedChecks.count - 10) more checks are available in technical output.")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                                .frame(maxWidth: .infinity, alignment: .leading)
                        }
                    }
                }

                DisclosureGroup(isExpanded: $showTechnicalOutput) {
                    Text(technicalOutput)
                        .font(.system(.caption, design: .monospaced))
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                        .padding(12)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(Color(nsColor: .textBackgroundColor), in: RoundedRectangle(cornerRadius: 8))
                        .overlay(
                            RoundedRectangle(cornerRadius: 8)
                                .stroke(Color(nsColor: .separatorColor), lineWidth: 1)
                        )
                } label: {
                    Text("Technical Output")
                        .font(.caption.weight(.semibold))
                }
            }
            .padding(14)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 8))
            .overlay(
                RoundedRectangle(cornerRadius: 8)
                    .stroke(Color(nsColor: .separatorColor), lineWidth: 1)
            )
        }
    }

    private var technicalOutput: String {
        if result.commandLine.isEmpty {
            return result.rawOutput
        }
        return """
        $ \(result.commandLine)
        exit \(result.exitCode)

        \(result.rawOutput.isEmpty ? "(no output)" : result.rawOutput)
        """
    }
}

private struct SetupTaskCheckRow: View {
    let check: SetupTaskCheck

    private var color: Color {
        switch check.state {
        case .passed: return .green
        case .warning: return .orange
        case .failed: return .red
        case .skipped: return .secondary
        }
    }

    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            Text(check.state.label)
                .font(.caption2.weight(.semibold))
                .foregroundStyle(color)
                .frame(width: 52, alignment: .leading)
            Text(check.message)
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 0)
        }
    }
}
