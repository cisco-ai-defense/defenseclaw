import SwiftUI

struct ManagedTextFileWorkspaceView: View {
    @Bindable var model: TextFileEditorModel
    let title: String
    let subtitle: String
    let emptyMessage: String
    var accessory: AnyView?

    init<Accessory: View>(
        model: TextFileEditorModel,
        title: String,
        subtitle: String,
        emptyMessage: String,
        @ViewBuilder accessory: () -> Accessory
    ) {
        self.model = model
        self.title = title
        self.subtitle = subtitle
        self.emptyMessage = emptyMessage
        self.accessory = AnyView(accessory())
    }

    init(
        model: TextFileEditorModel,
        title: String,
        subtitle: String,
        emptyMessage: String
    ) {
        self.model = model
        self.title = title
        self.subtitle = subtitle
        self.emptyMessage = emptyMessage
        self.accessory = nil
    }

    var body: some View {
        HSplitView {
            sidebar
                .frame(minWidth: 260, idealWidth: 310, maxWidth: 380)

            editor
                .frame(minWidth: 520)
        }
        .background(Color(nsColor: .windowBackgroundColor))
    }

    private var sidebar: some View {
        VStack(alignment: .leading, spacing: 14) {
            VStack(alignment: .leading, spacing: 4) {
                Text(title)
                    .font(.title3.weight(.semibold))
                Text(subtitle)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            searchField
            fileStats

            Divider()

            if model.groupedFiles.isEmpty {
                ContentUnavailableView(
                    emptyMessage,
                    systemImage: "doc.text.magnifyingglass",
                    description: Text("Try refreshing discovery or checking the runtime data directory.")
                )
            } else {
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 14) {
                        ForEach(model.groupedFiles, id: \.0) { groupName, files in
                            fileGroup(title: groupName, files: files)
                        }
                    }
                    .padding(.vertical, 2)
                }
            }

            HStack {
                Button {
                    model.reloadFiles()
                } label: {
                    Label("Refresh", systemImage: "arrow.clockwise")
                }

                Spacer()

                Text(model.statusMessage)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
        }
        .padding(18)
    }

    private var searchField: some View {
        HStack(spacing: 8) {
            Image(systemName: "magnifyingglass")
                .foregroundStyle(.secondary)
            TextField("Search files, sources, paths", text: $model.searchText)
                .textFieldStyle(.plain)
            if !model.searchText.isEmpty {
                Button {
                    model.searchText = ""
                } label: {
                    Image(systemName: "xmark.circle.fill")
                }
                .buttonStyle(.plain)
                .foregroundStyle(.secondary)
            }
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 8)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 8))
        .overlay(
            RoundedRectangle(cornerRadius: 8)
                .stroke(Color(nsColor: .separatorColor), lineWidth: 1)
        )
    }

    private var fileStats: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 8) {
                statChip(label: "Files", value: "\(model.files.count)")
                ForEach(model.kindCounts.prefix(3), id: \.0) { kind, count in
                    statChip(label: kind, value: "\(count)")
                }
            }

            if !model.sourceCounts.isEmpty {
                HStack(spacing: 8) {
                    ForEach(model.sourceCounts, id: \.0) { source, count in
                        statChip(label: source, value: "\(count)")
                    }
                }
            }
        }
    }

    private func statChip(label: String, value: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(value)
                .font(.headline.monospacedDigit())
            Text(label)
                .font(.caption2)
                .foregroundStyle(.secondary)
                .lineLimit(1)
        }
        .frame(minWidth: 52, alignment: .leading)
        .padding(.horizontal, 8)
        .padding(.vertical, 6)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 8))
    }

    private func fileGroup(title: String, files: [ManagedTextFile]) -> some View {
        VStack(alignment: .leading, spacing: 7) {
            Text(title.uppercased())
                .font(.caption2.weight(.semibold))
                .foregroundStyle(.secondary)
                .padding(.horizontal, 4)

            ForEach(files) { file in
                ManagedTextFileRow(
                    file: file,
                    isSelected: file.id == model.selectedFileID,
                    isDirty: file.id == model.selectedFileID && model.isDirty
                ) {
                    model.select(file)
                }
            }
        }
    }

    private var editor: some View {
        VStack(spacing: 0) {
            if let file = model.selectedFile {
                editorHeader(for: file)
                Divider()
                textEditor(for: file)
                Divider()
                editorFooter(for: file)
            } else {
                ContentUnavailableView(
                    emptyMessage,
                    systemImage: "doc.text",
                    description: Text("No editable YAML, JSON, or Rego files were discovered.")
                )
            }
        }
    }

    private func editorHeader(for file: ManagedTextFile) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .top, spacing: 12) {
                VStack(alignment: .leading, spacing: 4) {
                    HStack(spacing: 8) {
                        Text(file.displayName)
                            .font(.title3.weight(.semibold))
                            .lineLimit(1)

                        fileBadge(file.kind.rawValue, color: .blue)
                        fileBadge(file.source.rawValue, color: sourceColor(file.source))
                        if !file.isEditable {
                            fileBadge("Read-only", color: .secondary)
                        }
                        if model.isDirty {
                            fileBadge("Unsaved", color: .orange)
                        }
                    }

                    Text(file.relativePath)
                        .font(.caption.monospaced())
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }

                Spacer()

                HStack(spacing: 8) {
                    Button {
                        model.loadSelectedFile()
                    } label: {
                        Label("Reload", systemImage: "arrow.clockwise")
                    }
                    .disabled(model.isLoading)

                    Button {
                        model.validateContent()
                    } label: {
                        Label("Validate", systemImage: "checkmark.seal")
                    }

                    Button {
                        model.revert()
                    } label: {
                        Label("Revert", systemImage: "arrow.uturn.backward")
                    }
                    .disabled(!model.isDirty)

                    if file.isEditable {
                        Button {
                            model.save()
                        } label: {
                            Label("Save", systemImage: "square.and.arrow.down")
                        }
                        .buttonStyle(.borderedProminent)
                        .disabled(!model.isDirty || model.isSaving)
                    }
                }
            }

            if let accessory {
                accessory
            }
        }
        .padding(18)
    }

    private func textEditor(for file: ManagedTextFile) -> some View {
        ZStack(alignment: .topLeading) {
            TextEditor(text: $model.content)
                .font(.system(.body, design: .monospaced))
                .scrollContentBackground(.hidden)
                .padding(12)
                .background(Color(nsColor: .textBackgroundColor))
                .disabled(!file.isEditable)

            if model.isLoading {
                ProgressView()
                    .padding(18)
            }
        }
    }

    private func editorFooter(for file: ManagedTextFile) -> some View {
        HStack(spacing: 10) {
            Image(systemName: validationIcon(model.validation.state))
                .foregroundStyle(validationColor(model.validation.state))
            Text(model.validation.message)
                .foregroundStyle(model.validation.state == .invalid ? .red : .secondary)

            Spacer()

            Text(file.fullPath)
                .font(.caption.monospaced())
                .foregroundStyle(.secondary)
                .lineLimit(1)
                .truncationMode(.middle)
        }
        .font(.caption)
        .padding(.horizontal, 18)
        .padding(.vertical, 10)
        .background(Color(nsColor: .controlBackgroundColor))
    }

    private func fileBadge(_ text: String, color: Color) -> some View {
        Text(text)
            .font(.caption2.weight(.semibold))
            .padding(.horizontal, 7)
            .padding(.vertical, 3)
            .foregroundStyle(color)
            .background(color.opacity(0.12), in: Capsule())
    }

    private func sourceColor(_ source: ManagedTextFileSource) -> Color {
        switch source {
        case .runtime:
            return .green
        case .openClaw:
            return .purple
        case .project:
            return .indigo
        case .bundled:
            return .teal
        }
    }

    private func validationIcon(_ state: ValidationState) -> String {
        switch state {
        case .idle:
            return "circle"
        case .valid:
            return "checkmark.circle.fill"
        case .warning:
            return "exclamationmark.triangle.fill"
        case .invalid:
            return "xmark.octagon.fill"
        }
    }

    private func validationColor(_ state: ValidationState) -> Color {
        switch state {
        case .idle:
            return .secondary
        case .valid:
            return .green
        case .warning:
            return .orange
        case .invalid:
            return .red
        }
    }
}

private struct ManagedTextFileRow: View {
    let file: ManagedTextFile
    let isSelected: Bool
    let isDirty: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 10) {
                Image(systemName: iconName)
                    .foregroundStyle(iconColor)
                    .frame(width: 18)

                VStack(alignment: .leading, spacing: 3) {
                    HStack(spacing: 6) {
                        Text(file.displayName)
                            .font(.subheadline.weight(isSelected ? .semibold : .regular))
                            .lineLimit(1)
                        if isDirty {
                            Circle()
                                .fill(Color.orange)
                                .frame(width: 6, height: 6)
                        }
                    }

                    Text(file.relativePath)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }

                Spacer()

                Text(file.kind.rawValue)
                    .font(.caption2.weight(.medium))
                    .foregroundStyle(.secondary)
            }
            .padding(.horizontal, 9)
            .padding(.vertical, 8)
            .contentShape(Rectangle())
            .background(
                isSelected
                ? Color.accentColor.opacity(0.14)
                : Color(nsColor: .controlBackgroundColor).opacity(0.55),
                in: RoundedRectangle(cornerRadius: 8)
            )
            .overlay(
                RoundedRectangle(cornerRadius: 8)
                    .stroke(isSelected ? Color.accentColor.opacity(0.45) : Color.clear, lineWidth: 1)
            )
        }
        .buttonStyle(.plain)
    }

    private var iconName: String {
        switch file.kind {
        case .yaml:
            return "doc.plaintext"
        case .json:
            return "curlybraces"
        case .rego:
            return "function"
        case .text:
            return "doc.text"
        }
    }

    private var iconColor: Color {
        switch file.source {
        case .runtime:
            return .green
        case .openClaw:
            return .purple
        case .project:
            return .indigo
        case .bundled:
            return .teal
        }
    }
}
