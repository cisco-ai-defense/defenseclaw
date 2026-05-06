import Foundation
import Observation

@MainActor
@Observable
final class TextFileEditorModel {
    private let mode: ManagedWorkspaceMode

    var files: [ManagedTextFile] = []
    var selectedFileID: ManagedTextFile.ID?
    var searchText = ""
    var categoryFilter = "All"
    var sourceFilter = "All"
    var kindFilter = "All"
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

        return files.filter { file in
            let matchesCategory = categoryFilter == "All" || file.category == categoryFilter
            let matchesSource = sourceFilter == "All" || file.source.rawValue == sourceFilter
            let matchesKind = kindFilter == "All" || file.kind.rawValue == kindFilter
            guard matchesCategory, matchesSource, matchesKind else {
                return false
            }
            guard !query.isEmpty else {
                return true
            }

            return [
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

    var categoryOptions: [String] {
        ["All"] + Set(files.map(\.category)).sorted()
    }

    var sourceOptions: [String] {
        ["All"] + Set(files.map { $0.source.rawValue }).sorted()
    }

    var kindOptions: [String] {
        ["All"] + Set(files.map { $0.kind.rawValue }).sorted()
    }

    var editableCount: Int {
        files.filter(\.isEditable).count
    }

    var readOnlyCount: Int {
        files.count - editableCount
    }

    var activeFilterCount: Int {
        [categoryFilter, sourceFilter, kindFilter].filter { $0 != "All" }.count
            + (searchText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? 0 : 1)
    }

    var contentLineCount: Int {
        guard !content.isEmpty else {
            return 0
        }
        return content.split(separator: "\n", omittingEmptySubsequences: false).count
    }

    var contentCharacterCount: Int {
        content.count
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

    func clearFilters() {
        searchText = ""
        categoryFilter = "All"
        sourceFilter = "All"
        kindFilter = "All"
        selectFirstFilteredIfNeeded()
    }

    func selectFirstFilteredIfNeeded() {
        guard let current = selectedFileID,
              filteredFiles.contains(where: { $0.id == current }) else {
            selectedFileID = filteredFiles.first?.id
            loadSelectedFile()
            return
        }
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
