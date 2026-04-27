import SwiftUI

struct SetupView: View {
    @State private var model = SetupWorkspaceModel()

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
    }

    private var sidebar: some View {
        VStack(alignment: .leading, spacing: 14) {
            VStack(alignment: .leading, spacing: 4) {
                Text("Setup")
                    .font(.title3.weight(.semibold))
                Text("TUI wizard parity for scanners, gateway, guardrail, sinks, webhooks, and sandbox.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            List(selection: selection) {
                ForEach(model.groups) { group in
                    SetupSidebarRow(group: group)
                        .tag(group.id)
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
            HStack(spacing: 12) {
                Label(model.selectedGroup.title, systemImage: model.selectedGroup.systemImage)
                    .font(.title2.weight(.semibold))
                Spacer()
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

            Divider()

            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    Text(model.selectedGroup.subtitle)
                        .font(.subheadline)
                        .foregroundStyle(.secondary)

                    if !model.selectedGroup.fields.isEmpty {
                        SetupFieldSection(model: model, group: model.selectedGroup)
                    }

                    if !model.selectedGroup.workflows.isEmpty {
                        SetupWorkflowSection(model: model, group: model.selectedGroup)
                    }

                    if !model.commandOutput.isEmpty {
                        commandOutput
                    }
                }
                .padding(18)
            }
        }
    }

    private var commandOutput: some View {
        VStack(alignment: .leading, spacing: 10) {
            Label("Task Output", systemImage: "terminal")
                .font(.headline)
            Text(model.commandOutput)
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
        }
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

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label("Configuration", systemImage: "slider.horizontal.3")
                .font(.headline)

            LazyVGrid(columns: [GridItem(.adaptive(minimum: 270), spacing: 12)], spacing: 12) {
                ForEach(group.fields) { field in
                    SetupFieldCard(model: model, field: field)
                }
            }
        }
    }
}

private struct SetupFieldCard: View {
    @Bindable var model: SetupWorkspaceModel
    let field: SetupField

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text(field.label)
                    .font(.subheadline.weight(.semibold))
                    .lineLimit(1)
                Spacer()
                Text(field.path)
                    .font(.caption2.monospaced())
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
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

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label("Guided Workflows", systemImage: "play.circle")
                .font(.headline)

            ForEach(group.workflows) { workflow in
                SetupWorkflowCard(model: model, workflow: workflow)
            }
        }
    }
}

private struct SetupWorkflowCard: View {
    @Bindable var model: SetupWorkspaceModel
    let workflow: SetupWorkflow

    private var isRunning: Bool {
        model.runningWorkflowID == workflow.id
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

            if !workflow.fields.isEmpty {
                LazyVGrid(columns: [GridItem(.adaptive(minimum: 220), spacing: 10)], spacing: 10) {
                    ForEach(workflow.fields) { field in
                        workflowField(field)
                    }
                }
            }

            Text(model.commandPreview(for: workflow))
                .font(.caption.monospaced())
                .foregroundStyle(.secondary)
                .lineLimit(2)
                .truncationMode(.middle)
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
