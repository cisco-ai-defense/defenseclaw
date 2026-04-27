import AppKit
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
                .frame(minWidth: 300, idealWidth: 340, maxWidth: 440)

            editor
                .frame(minWidth: 560)
        }
        .background(Color(nsColor: .windowBackgroundColor))
        .onChange(of: model.categoryFilter) { _, _ in model.selectFirstFilteredIfNeeded() }
        .onChange(of: model.sourceFilter) { _, _ in model.selectFirstFilteredIfNeeded() }
        .onChange(of: model.kindFilter) { _, _ in model.selectFirstFilteredIfNeeded() }
        .onChange(of: model.searchText) { _, _ in model.selectFirstFilteredIfNeeded() }
    }

    private var sidebar: some View {
        VStack(alignment: .leading, spacing: 14) {
            VStack(alignment: .leading, spacing: 5) {
                Text(title)
                    .font(.title3.weight(.semibold))
                Text(subtitle)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            searchField
            filters
            fileStats

            Divider()

            if model.groupedFiles.isEmpty {
                ContentUnavailableView(
                    model.files.isEmpty ? emptyMessage : "No files match these filters",
                    systemImage: "doc.text.magnifyingglass",
                    description: Text(model.files.isEmpty
                                      ? "Try refreshing discovery or checking the runtime data directory."
                                      : "Clear search and filters to show every managed file.")
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

                if model.activeFilterCount > 0 {
                    Button("Clear") {
                        model.clearFilters()
                    }
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
            TextField("Search files, categories, paths", text: $model.searchText)
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

    private var filters: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 8) {
                filterPicker(title: "Category", selection: $model.categoryFilter, options: model.categoryOptions)
                filterPicker(title: "Source", selection: $model.sourceFilter, options: model.sourceOptions)
            }
            filterPicker(title: "Format", selection: $model.kindFilter, options: model.kindOptions)
        }
    }

    private func filterPicker(title: String, selection: Binding<String>, options: [String]) -> some View {
        Picker(title, selection: selection) {
            ForEach(options, id: \.self) { option in
                Text(option).tag(option)
            }
        }
        .labelsHidden()
        .pickerStyle(.menu)
        .frame(maxWidth: .infinity)
        .help(title)
    }

    private var fileStats: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 8) {
                statChip(label: "Files", value: "\(model.files.count)")
                statChip(label: "Shown", value: "\(model.filteredFiles.count)")
                statChip(label: "Writable", value: "\(model.editableCount)")
                if model.readOnlyCount > 0 {
                    statChip(label: "Read-only", value: "\(model.readOnlyCount)")
                }
            }

            if !model.kindCounts.isEmpty {
                HStack(spacing: 8) {
                    ForEach(model.kindCounts.prefix(3), id: \.0) { kind, count in
                        statChip(label: kind, value: "\(count)")
                    }
                }
            }

            if !model.sourceCounts.isEmpty {
                HStack(spacing: 8) {
                    ForEach(model.sourceCounts.prefix(3), id: \.0) { source, count in
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

                    HStack(spacing: 12) {
                        Label(file.category, systemImage: "folder")
                        Label(file.group, systemImage: "square.grid.2x2")
                    }
                    .font(.caption)
                    .foregroundStyle(.secondary)
                }

                Spacer()

                HStack(spacing: 8) {
                    Button {
                        reveal(file)
                    } label: {
                        Image(systemName: "folder")
                    }
                    .help("Reveal in Finder")

                    Button {
                        copyPath(file)
                    } label: {
                        Image(systemName: "doc.on.doc")
                    }
                    .help("Copy path")

                    Button {
                        model.loadSelectedFile()
                    } label: {
                        Image(systemName: "arrow.clockwise")
                    }
                    .disabled(model.isLoading)
                    .help("Reload file")

                    Button {
                        model.validateContent()
                    } label: {
                        Image(systemName: "checkmark.seal")
                    }
                    .help("Validate")

                    Button {
                        model.revert()
                    } label: {
                        Image(systemName: "arrow.uturn.backward")
                    }
                    .disabled(!model.isDirty)
                    .help("Revert changes")

                    if file.isEditable {
                        Button {
                            model.save()
                        } label: {
                            Image(systemName: "square.and.arrow.down")
                        }
                        .buttonStyle(.borderedProminent)
                        .disabled(!model.isDirty || model.isSaving)
                        .help("Save")
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

            if !file.isEditable {
                HStack(spacing: 8) {
                    Image(systemName: "lock")
                    Text("Read-only reference file")
                }
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)
                .padding(.horizontal, 10)
                .padding(.vertical, 6)
                .background(.regularMaterial, in: Capsule())
                .padding(16)
            }
        }
    }

    private func editorFooter(for file: ManagedTextFile) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 10) {
                Image(systemName: validationIcon(model.validation.state))
                    .foregroundStyle(validationColor(model.validation.state))
                Text(model.validation.message)
                    .foregroundStyle(model.validation.state == .invalid ? .red : .secondary)
                    .lineLimit(2)

                Spacer()

                Text("\(model.contentLineCount) lines")
                Text("\(model.contentCharacterCount) chars")
                Text(file.isEditable ? "Writable" : "Read-only")
            }

            HStack(spacing: 12) {
                metadataChip("Path", file.fullPath)
                metadataChip("Source", file.source.rawValue)
                metadataChip("Format", file.kind.rawValue)
            }
        }
        .font(.caption)
        .padding(.horizontal, 18)
        .padding(.vertical, 10)
        .background(Color(nsColor: .controlBackgroundColor))
    }

    private func metadataChip(_ label: String, _ value: String) -> some View {
        HStack(spacing: 4) {
            Text(label)
                .foregroundStyle(.secondary)
            Text(value)
                .font(.caption.monospaced())
                .lineLimit(1)
                .truncationMode(.middle)
                .textSelection(.enabled)
        }
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

    private func reveal(_ file: ManagedTextFile) {
        NSWorkspace.shared.activateFileViewerSelecting([file.url])
    }

    private func copyPath(_ file: ManagedTextFile) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(file.fullPath, forType: .string)
        model.statusMessage = "Copied \(file.displayName) path"
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
                        .font(.caption2.monospaced())
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)

                    HStack(spacing: 6) {
                        Text(file.kind.rawValue)
                        Text(file.source.rawValue)
                        if !file.isEditable {
                            Text("Read-only")
                        }
                    }
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                }

                Spacer()
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
            return "checklist.checked"
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
