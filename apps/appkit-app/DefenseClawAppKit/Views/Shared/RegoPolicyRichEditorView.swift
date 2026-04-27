import SwiftUI

struct RegoPolicyRichEditorView: View {
    @Binding var content: String
    let isEditable: Bool
    let openSource: () -> Void

    @State private var document = RegoPolicyDocument(packageName: "", imports: [], rules: [])
    @State private var lastLoadedContent = ""
    @State private var isUpdatingContent = false
    @State private var isLoadingDocument = false

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            editorNotice

            Divider()

            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    packageSection
                    importsSection
                    rulesSection
                }
                .padding(18)
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
            guard !isLoadingDocument else {
                return
            }
            isUpdatingContent = true
            content = RegoPolicyDocumentCodec.serialize(newValue)
            lastLoadedContent = content
            DispatchQueue.main.async {
                isUpdatingContent = false
            }
        }
    }

    private var editorNotice: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: "checklist.checked")
                .foregroundStyle(.purple)

            VStack(alignment: .leading, spacing: 3) {
                Text("OPA / Rego Rich Editor")
                    .font(.subheadline.weight(.semibold))
                Text("Edit package, imports, and rule blocks as separate policy sections. Use Source for advanced OPA syntax, comments, and exact formatting.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
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

    private var packageSection: some View {
        RichPolicySection(title: "Package", systemImage: "shippingbox") {
            TextField("defenseclaw.policy", text: $document.packageName)
                .textFieldStyle(.roundedBorder)
                .disabled(!isEditable)
            Text("OPA uses the package as the namespace for these rules.")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }

    private var importsSection: some View {
        RichPolicySection(title: "Imports", systemImage: "arrow.down.doc") {
            if document.imports.isEmpty {
                Text("No imports.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            ForEach(document.imports.indices, id: \.self) { index in
                HStack(spacing: 8) {
                    TextField("data.defenseclaw.helpers", text: importBinding(index))
                        .textFieldStyle(.roundedBorder)
                        .disabled(!isEditable)
                    if isEditable {
                        Button(role: .destructive) {
                            document.imports.remove(at: index)
                        } label: {
                            Image(systemName: "trash")
                        }
                        .buttonStyle(.plain)
                    }
                }
            }

            if isEditable {
                Button {
                    document.imports.append("")
                } label: {
                    Label("Add Import", systemImage: "plus")
                }
                .controlSize(.small)
            }
        }
    }

    private var rulesSection: some View {
        RichPolicySection(title: "Rules", systemImage: "list.bullet.rectangle") {
            if document.rules.isEmpty {
                Text("No rules yet.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            ForEach(document.rules.indices, id: \.self) { index in
                VStack(alignment: .leading, spacing: 8) {
                    HStack {
                        TextField("Rule name", text: ruleTitleBinding(index))
                            .textFieldStyle(.roundedBorder)
                            .disabled(!isEditable)
                        if isEditable {
                            Button(role: .destructive) {
                                document.rules.remove(at: index)
                            } label: {
                                Image(systemName: "trash")
                            }
                            .buttonStyle(.plain)
                        }
                    }

                    TextEditor(text: ruleBodyBinding(index))
                        .font(.system(.body, design: .monospaced))
                        .frame(minHeight: 130)
                        .scrollContentBackground(.hidden)
                        .padding(8)
                        .background(Color(nsColor: .textBackgroundColor), in: RoundedRectangle(cornerRadius: 8))
                        .overlay(
                            RoundedRectangle(cornerRadius: 8)
                                .stroke(Color(nsColor: .separatorColor), lineWidth: 1)
                        )
                        .disabled(!isEditable)
                }
                .padding(12)
                .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 8))
                .overlay(
                    RoundedRectangle(cornerRadius: 8)
                        .stroke(Color(nsColor: .separatorColor), lineWidth: 1)
                )
            }

            if isEditable {
                Button {
                    document.rules.append(RegoRuleBlock(title: "allow", body: "allow if {\n    true\n}"))
                } label: {
                    Label("Add Rule", systemImage: "plus")
                }
                .controlSize(.small)
            }
        }
    }

    private func loadFromContent() {
        isLoadingDocument = true
        document = RegoPolicyDocumentCodec.parse(content)
        lastLoadedContent = content
        DispatchQueue.main.async {
            isLoadingDocument = false
        }
    }

    private func importBinding(_ index: Int) -> Binding<String> {
        Binding(
            get: {
                guard document.imports.indices.contains(index) else {
                    return ""
                }
                return document.imports[index]
            },
            set: { newValue in
                guard document.imports.indices.contains(index) else {
                    return
                }
                document.imports[index] = newValue
            }
        )
    }

    private func ruleTitleBinding(_ index: Int) -> Binding<String> {
        Binding(
            get: {
                guard document.rules.indices.contains(index) else {
                    return ""
                }
                return document.rules[index].title
            },
            set: { newValue in
                guard document.rules.indices.contains(index) else {
                    return
                }
                document.rules[index].title = newValue
            }
        )
    }

    private func ruleBodyBinding(_ index: Int) -> Binding<String> {
        Binding(
            get: {
                guard document.rules.indices.contains(index) else {
                    return ""
                }
                return document.rules[index].body
            },
            set: { newValue in
                guard document.rules.indices.contains(index) else {
                    return
                }
                document.rules[index].body = newValue
                document.rules[index].title = RegoPolicyDocumentCodec.parse("package tmp\n\n\(newValue)").rules.first?.title ?? document.rules[index].title
            }
        )
    }
}

private struct RichPolicySection<Content: View>: View {
    let title: String
    let systemImage: String
    @ViewBuilder var content: () -> Content

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label(title, systemImage: systemImage)
                .font(.headline)
            content()
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
