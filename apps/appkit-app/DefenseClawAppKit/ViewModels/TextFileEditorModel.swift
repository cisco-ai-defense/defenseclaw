import Foundation
import Observation

@MainActor
@Observable
final class TextFileEditorModel {
    private let mode: ManagedWorkspaceMode

    var files: [ManagedTextFile] = []
    var selectedFileID: ManagedTextFile.ID?
    var searchText = ""
    var content = ""
    var originalContent = ""
    var validation: ManagedFileValidation = .idle
    var statusMessage = ""
    var isLoading = false
    var isSaving = false

    init(mode: ManagedWorkspaceMode) {
        self.mode = mode
        reloadFiles(selectFirst: true)
    }

    var selectedFile: ManagedTextFile? {
        files.first { $0.id == selectedFileID }
    }

    var filteredFiles: [ManagedTextFile] {
        let query = searchText.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !query.isEmpty else {
            return files
        }

        return files.filter { file in
            [
                file.displayName,
                file.relativePath,
                file.category,
                file.group,
                file.source.rawValue,
                file.kind.rawValue
            ]
            .contains { $0.lowercased().contains(query) }
        }
    }

    var groupedFiles: [(String, [ManagedTextFile])] {
        Dictionary(grouping: filteredFiles, by: \.category)
            .map { ($0.key, $0.value.sorted { $0.relativePath < $1.relativePath }) }
            .sorted { $0.0 < $1.0 }
    }

    var isDirty: Bool {
        content != originalContent
    }

    var sourceCounts: [(String, Int)] {
        Dictionary(grouping: files, by: { $0.source.rawValue })
            .map { ($0.key, $0.value.count) }
            .sorted { $0.0 < $1.0 }
    }

    var kindCounts: [(String, Int)] {
        Dictionary(grouping: files, by: { $0.kind.rawValue })
            .map { ($0.key, $0.value.count) }
            .sorted { $0.0 < $1.0 }
    }

    func reloadFiles(selectFirst: Bool = false) {
        let previousSelection = selectedFileID
        files = TextFileWorkspace.discover(mode: mode)

        if selectFirst || previousSelection == nil || !files.contains(where: { $0.id == previousSelection }) {
            selectedFileID = files.first?.id
        } else {
            selectedFileID = previousSelection
        }

        loadSelectedFile()
        statusMessage = "\(files.count) files discovered"
    }

    func select(_ file: ManagedTextFile) {
        guard file.id != selectedFileID else {
            return
        }

        selectedFileID = file.id
        loadSelectedFile()
    }

    func loadSelectedFile() {
        guard let selectedFile else {
            content = ""
            originalContent = ""
            validation = .idle
            statusMessage = "No editable file found"
            return
        }

        isLoading = true
        defer { isLoading = false }

        do {
            content = try TextFileWorkspace.load(selectedFile)
            originalContent = content
            validation = .idle
            statusMessage = "Loaded \(selectedFile.relativePath)"
        } catch {
            content = ""
            originalContent = ""
            validation = .invalid("Load failed: \(error.localizedDescription)")
            statusMessage = "Could not load \(selectedFile.relativePath)"
        }
    }

    @discardableResult
    func validateContent() -> ManagedFileValidation {
        guard let selectedFile else {
            validation = .invalid("No file selected")
            return validation
        }

        validation = TextFileWorkspace.validate(content: content, kind: selectedFile.kind)
        return validation
    }

    func save() {
        guard let selectedFile else {
            statusMessage = "No file selected"
            return
        }

        let result = validateContent()
        guard result.state != .invalid else {
            statusMessage = "Fix validation errors before saving"
            return
        }

        isSaving = true
        defer { isSaving = false }

        do {
            try TextFileWorkspace.save(content, to: selectedFile)
            originalContent = content
            statusMessage = "Saved \(selectedFile.relativePath)"
        } catch {
            statusMessage = "Save failed: \(error.localizedDescription)"
        }
    }

    func revert() {
        content = originalContent
        validation = .idle
        statusMessage = selectedFile.map { "Reverted \($0.relativePath)" } ?? ""
    }
}
