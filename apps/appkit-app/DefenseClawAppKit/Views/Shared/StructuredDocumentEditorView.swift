import SwiftUI

struct StructuredDocumentEditorView: View {
    @Binding var content: String
    let kind: ManagedTextFileKind
    let isEditable: Bool
    let documentTitle: String
    let documentSummary: String
    let openSource: () -> Void

    @State private var document: StructuredValue = .object([])
    @State private var parseError: String?
    @State private var lastLoadedContent = ""
    @State private var isUpdatingContent = false
    @State private var isLoadingDocument = false

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            richEditorNotice

            Divider()

            if let parseError {
                ContentUnavailableView(
                    "Rich editor could not parse this file",
                    systemImage: "exclamationmark.triangle",
                    description: Text(parseError)
                )
                .frame(maxWidth: .infinity, maxHeight: .infinity)

                Button {
                    openSource()
                } label: {
                    Label("Open Source Editor", systemImage: "chevron.left.forwardslash.chevron.right")
                }
                .padding()
            } else {
                ScrollView {
                    StructuredValueEditor(value: $document, label: "Root", isEditable: isEditable, depth: 0)
                        .padding(18)
                }
            }
        }
        .onAppear(perform: loadFromContent)
        .onChange(of: content) { _, newValue in
            guard !isUpdatingContent, newValue != lastLoadedContent else {
                return
            }
            loadFromContent()
        }
        .onChange(of: document) { _, newValue in
            guard parseError == nil, !isLoadingDocument else {
                return
            }
            do {
                let serialized = try StructuredPolicyDocumentCodec.serialize(newValue, kind: kind)
                isUpdatingContent = true
                content = serialized
                lastLoadedContent = serialized
                DispatchQueue.main.async {
                    isUpdatingContent = false
                }
            } catch {
                parseError = error.localizedDescription
            }
        }
    }

    private var richEditorNotice: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: "square.grid.2x2")
                .foregroundStyle(.blue)

            VStack(alignment: .leading, spacing: 3) {
                Text(documentTitle)
                    .font(.subheadline.weight(.semibold))
                Text(documentSummary)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                Text("Rich edits produce normalized \(kind.rawValue). Use Source when exact comments, quoting, anchors, or hand formatting matter.")
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            Spacer()

            Button {
                openSource()
            } label: {
                Label("Source", systemImage: "chevron.left.forwardslash.chevron.right")
            }
            .controlSize(.small)
        }
        .padding(18)
        .background(Color(nsColor: .controlBackgroundColor))
    }

    private func loadFromContent() {
        do {
            isLoadingDocument = true
            document = try StructuredPolicyDocumentCodec.parse(content: content, kind: kind)
            parseError = nil
            lastLoadedContent = content
            DispatchQueue.main.async {
                isLoadingDocument = false
            }
        } catch {
            parseError = error.localizedDescription
            lastLoadedContent = content
            isLoadingDocument = false
        }
    }
}

private struct StructuredValueEditor: View {
    @Binding var value: StructuredValue
    let label: String
    let isEditable: Bool
    let depth: Int

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            switch value {
            case .object:
                objectEditor
            case .array:
                arrayEditor
            case .string:
                scalarTextEditor
            case .number:
                scalarNumberEditor
            case .bool:
                scalarBoolEditor
            case .null:
                nullEditor
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private var objectEntries: [StructuredEntry] {
        guard case .object(let entries) = value else {
            return []
        }
        return entries
    }

    private var arrayValues: [StructuredValue] {
        guard case .array(let values) = value else {
            return []
        }
        return values
    }

    private var objectEditor: some View {
        VStack(alignment: .leading, spacing: 10) {
            sectionHeader(title: label, subtitle: "\(objectEntries.count) fields", systemImage: "folder")

            if objectEntries.isEmpty {
                Text("No fields yet.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            ForEach(Array(objectEntries.enumerated()), id: \.element.id) { index, entry in
                StructuredEntryEditor(
                    entry: entryBinding(index),
                    isEditable: isEditable,
                    depth: depth + 1,
                    delete: { removeObjectEntry(at: index) }
                )
            }

            if isEditable {
                Button {
                    appendObjectEntry()
                } label: {
                    Label("Add Field", systemImage: "plus")
                }
                .controlSize(.small)
            }
        }
        .padding(12)
        .background(depth == 0 ? Color.clear : Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 8))
        .overlay(
            RoundedRectangle(cornerRadius: 8)
                .stroke(depth == 0 ? Color.clear : Color(nsColor: .separatorColor), lineWidth: 1)
        )
    }

    private var arrayEditor: some View {
        VStack(alignment: .leading, spacing: 10) {
            sectionHeader(title: label, subtitle: "\(arrayValues.count) items", systemImage: "list.bullet")

            if arrayValues.isEmpty {
                Text("No items yet.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            ForEach(Array(arrayValues.enumerated()), id: \.offset) { index, _ in
                VStack(alignment: .leading, spacing: 8) {
                    HStack {
                        Text("Item \(index + 1)")
                            .font(.caption.weight(.semibold))
                            .foregroundStyle(.secondary)
                        Spacer()
                        typePicker(for: arrayValueBinding(index))
                        if isEditable {
                            Button(role: .destructive) {
                                removeArrayValue(at: index)
                            } label: {
                                Image(systemName: "trash")
                            }
                            .buttonStyle(.plain)
                        }
                    }

                    StructuredValueEditor(
                        value: arrayValueBinding(index),
                        label: "Item \(index + 1)",
                        isEditable: isEditable,
                        depth: depth + 1
                    )
                }
                .padding(10)
                .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 8))
                .overlay(
                    RoundedRectangle(cornerRadius: 8)
                        .stroke(Color(nsColor: .separatorColor), lineWidth: 1)
                )
            }

            if isEditable {
                Button {
                    appendArrayValue()
                } label: {
                    Label("Add Item", systemImage: "plus")
                }
                .controlSize(.small)
            }
        }
        .padding(12)
        .background(depth == 0 ? Color.clear : Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 8))
        .overlay(
            RoundedRectangle(cornerRadius: 8)
                .stroke(depth == 0 ? Color.clear : Color(nsColor: .separatorColor), lineWidth: 1)
        )
    }

    private var scalarTextEditor: some View {
        VStack(alignment: .leading, spacing: 6) {
            scalarHeader
            if isSecretLikeString {
                SecureField("Secret value", text: textBinding)
                    .textFieldStyle(.roundedBorder)
                    .privacySensitive()
                    .disabled(!isEditable)
                Text("Masked because this field name looks secret-like. Prefer *_env fields or the Secrets setup flow for normal use.")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                TextField("Text", text: textBinding)
                    .textFieldStyle(.roundedBorder)
                    .disabled(!isEditable)
            }
        }
    }

    private var scalarNumberEditor: some View {
        VStack(alignment: .leading, spacing: 6) {
            scalarHeader
            TextField("Number", text: Binding(
                get: {
                    if case .number(let number) = value {
                        return number
                    }
                    return ""
                },
                set: { value = .number($0) }
            ))
            .textFieldStyle(.roundedBorder)
            .disabled(!isEditable)
        }
    }

    private var scalarBoolEditor: some View {
        HStack {
            scalarHeader
            Spacer()
            Toggle("", isOn: Binding(
                get: {
                    if case .bool(let bool) = value {
                        return bool
                    }
                    return false
                },
                set: { value = .bool($0) }
            ))
            .labelsHidden()
            .disabled(!isEditable)
        }
    }

    private var nullEditor: some View {
        HStack(spacing: 8) {
            scalarHeader
            Text("No value")
                .font(.caption)
                .foregroundStyle(.secondary)
            Spacer()
            if isEditable {
                Button("Set Text") {
                    value = .string("")
                }
                .controlSize(.small)
            }
        }
    }

    private var scalarHeader: some View {
        HStack(spacing: 8) {
            Text(label)
                .font(.subheadline.weight(.semibold))
                .lineLimit(1)
            Text(value.typeLabel)
                .font(.caption2.weight(.semibold))
                .foregroundStyle(.secondary)
                .padding(.horizontal, 6)
                .padding(.vertical, 2)
                .background(Color.secondary.opacity(0.12), in: Capsule())
            if isSecretLikeString {
                Text("Secret")
                    .font(.caption2.weight(.semibold))
                    .foregroundStyle(.orange)
                    .padding(.horizontal, 6)
                    .padding(.vertical, 2)
                    .background(Color.orange.opacity(0.14), in: Capsule())
            }
        }
    }

    private var textBinding: Binding<String> {
        Binding(
            get: {
                if case .string(let string) = value {
                    return string
                }
                return ""
            },
            set: { value = .string($0) }
        )
    }

    private var isSecretLikeString: Bool {
        guard case .string = value else {
            return false
        }
        return Self.isSecretLike(label)
    }

    private static func isSecretLike(_ label: String) -> Bool {
        let normalized = label
            .lowercased()
            .map { character in
                character.isLetter || character.isNumber ? character : "_"
            }
            .reduce(into: "") { partial, character in
                if character == "_" && partial.last == "_" {
                    return
                }
                partial.append(character)
            }
            .trimmingCharacters(in: CharacterSet(charactersIn: "_"))

        if normalized.hasSuffix("_env") ||
            normalized.hasSuffix("_env_var") ||
            normalized.hasSuffix("_environment") {
            return false
        }

        let exactPatterns = [
            "api_key",
            "access_token",
            "auth_token",
            "bot_token",
            "client_secret",
            "private_key",
            "routing_key",
            "secret_key",
            "webhook_secret"
        ]
        if exactPatterns.contains(where: normalized.contains) {
            return true
        }

        let tokens = Set(normalized.split(separator: "_").map(String.init))
        return tokens.contains("password") ||
            tokens.contains("passwd") ||
            tokens.contains("secret") ||
            tokens.contains("token") ||
            tokens.contains("credential")
    }

    private func sectionHeader(title: String, subtitle: String, systemImage: String) -> some View {
        HStack(spacing: 8) {
            Image(systemName: systemImage)
                .foregroundStyle(.secondary)
            Text(title)
                .font(.subheadline.weight(.semibold))
            Text(subtitle)
                .font(.caption)
                .foregroundStyle(.secondary)
            Spacer()
            typePicker(for: $value)
        }
    }

    private func entryBinding(_ index: Int) -> Binding<StructuredEntry> {
        Binding(
            get: {
                guard case .object(let entries) = value, entries.indices.contains(index) else {
                    return StructuredEntry(key: "", value: .string(""))
                }
                return entries[index]
            },
            set: { newEntry in
                guard case .object(var entries) = value, entries.indices.contains(index) else {
                    return
                }
                entries[index] = newEntry
                value = .object(entries)
            }
        )
    }

    private func arrayValueBinding(_ index: Int) -> Binding<StructuredValue> {
        Binding(
            get: {
                guard case .array(let values) = value, values.indices.contains(index) else {
                    return .string("")
                }
                return values[index]
            },
            set: { newValue in
                guard case .array(var values) = value, values.indices.contains(index) else {
                    return
                }
                values[index] = newValue
                value = .array(values)
            }
        )
    }

    private func appendObjectEntry() {
        guard case .object(var entries) = value else {
            return
        }
        entries.append(StructuredEntry(key: "new_field", value: .string("")))
        value = .object(entries)
    }

    private func removeObjectEntry(at index: Int) {
        guard case .object(var entries) = value, entries.indices.contains(index) else {
            return
        }
        entries.remove(at: index)
        value = .object(entries)
    }

    private func appendArrayValue() {
        guard case .array(var values) = value else {
            return
        }
        values.append(.string(""))
        value = .array(values)
    }

    private func removeArrayValue(at index: Int) {
        guard case .array(var values) = value, values.indices.contains(index) else {
            return
        }
        values.remove(at: index)
        value = .array(values)
    }

    private func typePicker(for binding: Binding<StructuredValue>) -> some View {
        Menu {
            Button("Text") { binding.wrappedValue = .string("") }
            Button("Number") { binding.wrappedValue = .number("0") }
            Button("Toggle") { binding.wrappedValue = .bool(false) }
            Button("Group") { binding.wrappedValue = .object([]) }
            Button("List") { binding.wrappedValue = .array([]) }
            Button("Empty") { binding.wrappedValue = .null }
        } label: {
            Label(binding.wrappedValue.typeLabel, systemImage: "switch.2")
        }
        .controlSize(.small)
        .disabled(!isEditable)
    }
}

private struct StructuredEntryEditor: View {
    @Binding var entry: StructuredEntry
    let isEditable: Bool
    let depth: Int
    let delete: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 8) {
                TextField("Field name", text: $entry.key)
                    .textFieldStyle(.roundedBorder)
                    .font(.subheadline.weight(.semibold))
                    .disabled(!isEditable)

                typePicker

                if isEditable {
                    Button(role: .destructive, action: delete) {
                        Image(systemName: "trash")
                    }
                    .buttonStyle(.plain)
                    .help("Remove field")
                }
            }

            StructuredValueEditor(value: $entry.value, label: entry.key.isEmpty ? "Value" : entry.key, isEditable: isEditable, depth: depth)
                .padding(.leading, 10)
        }
        .padding(10)
        .background(Color(nsColor: .textBackgroundColor).opacity(0.45), in: RoundedRectangle(cornerRadius: 8))
    }

    private var typePicker: some View {
        Menu {
            Button("Text") { entry.value = .string("") }
            Button("Number") { entry.value = .number("0") }
            Button("Toggle") { entry.value = .bool(false) }
            Button("Group") { entry.value = .object([]) }
            Button("List") { entry.value = .array([]) }
            Button("Empty") { entry.value = .null }
        } label: {
            Label(entry.value.typeLabel, systemImage: "switch.2")
        }
        .controlSize(.small)
        .disabled(!isEditable)
    }
}
