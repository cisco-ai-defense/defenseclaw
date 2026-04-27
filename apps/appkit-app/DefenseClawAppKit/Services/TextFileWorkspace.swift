import Foundation
import Yams

struct TextFileWorkspace {
    private static let editableExtensions: Set<String> = ["yaml", "yml", "json", "rego"]
    private static let maxEditableFileBytes = 2_000_000

    static func discover(mode: ManagedWorkspaceMode) -> [ManagedTextFile] {
        switch mode {
        case .configuration:
            return discoverConfigurationFiles()
        case .policy:
            return discoverPolicyFiles()
        }
    }

    static func load(_ file: ManagedTextFile) throws -> String {
        try String(contentsOf: file.url, encoding: .utf8)
    }

    static func save(_ content: String, to file: ManagedTextFile) throws {
        guard file.isEditable else {
            throw TextFileWorkspaceError.readOnly(file.relativePath)
        }

        let directory = file.url.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        try content.write(to: file.url, atomically: true, encoding: .utf8)

        if file.url.lastPathComponent == "config.yaml",
           file.url.path.contains("/.defenseclaw/") {
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.url.path)
        }
    }

    static func validate(content: String, kind: ManagedTextFileKind) -> ManagedFileValidation {
        let trimmed = content.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            return .invalid("File is empty")
        }

        switch kind {
        case .yaml:
            do {
                _ = try Yams.load(yaml: content)
                return .valid("YAML parsed successfully")
            } catch {
                return .invalid("YAML error: \(error.localizedDescription)")
            }
        case .json:
            guard let data = content.data(using: .utf8) else {
                return .invalid("JSON is not valid UTF-8")
            }
            do {
                _ = try JSONSerialization.jsonObject(with: data)
                return .valid("JSON parsed successfully")
            } catch {
                return .invalid("JSON error: \(error.localizedDescription)")
            }
        case .rego:
            let basic = validateRegoBasics(content)
            guard basic.state != .invalid else {
                return basic
            }
            return .warning("Basic Rego checks passed. Install OPA for full policy compilation checks.")
        case .text:
            return .valid("Text file is readable")
        }
    }

    private static func discoverConfigurationFiles() -> [ManagedTextFile] {
        var files: [ManagedTextFile] = []
        let home = FileManager.default.homeDirectoryForCurrentUser
        let defenseClawHome = home.appendingPathComponent(".defenseclaw", isDirectory: true)
        let openClawHome = home.appendingPathComponent(".openclaw", isDirectory: true)

        appendIfPresent(
            defenseClawHome.appendingPathComponent("config.yaml"),
            to: &files,
            category: "Primary Config",
            group: "DefenseClaw",
            source: .runtime,
            base: home
        )
        appendIfPresent(
            defenseClawHome.appendingPathComponent("litellm_config.yaml"),
            to: &files,
            category: "LLM Routing",
            group: "DefenseClaw",
            source: .runtime,
            base: home
        )
        appendIfPresent(
            defenseClawHome.appendingPathComponent("guardrail_runtime.json"),
            to: &files,
            category: "Guardrail Runtime",
            group: "DefenseClaw",
            source: .runtime,
            base: home
        )
        appendIfPresent(
            openClawHome.appendingPathComponent("openclaw.json"),
            to: &files,
            category: "Coding Agents",
            group: "OpenClaw",
            source: .openClaw,
            base: home
        )

        files.append(contentsOf: scanDirectory(
            defenseClawHome,
            source: .runtime,
            base: home,
            categoryResolver: configCategory,
            exclusion: shouldExcludeConfig
        ))
        files.append(contentsOf: scanDirectory(
            openClawHome,
            source: .openClaw,
            base: home,
            categoryResolver: configCategory,
            exclusion: shouldExcludeConfig
        ))

        if let resources = Bundle.main.resourceURL {
            for relativePath in [
                "bundles/local_observability_stack",
                "bundles/splunk_local_bridge",
                "policies/scanners"
            ] {
                let url = resources.appendingPathComponent(relativePath, isDirectory: true)
                files.append(contentsOf: scanDirectory(
                    url,
                    source: .bundled,
                    base: resources,
                    categoryResolver: configCategory,
                    exclusion: shouldExcludeConfig,
                    isEditable: false
                ))
            }
        }

        if let root = projectRoot() {
            for relativePath in [
                "bundles/local_observability_stack",
                "bundles/splunk_local_bridge",
                "policies/scanners"
            ] {
                let url = root.appendingPathComponent(relativePath, isDirectory: true)
                files.append(contentsOf: scanDirectory(
                    url,
                    source: .project,
                    base: root,
                    categoryResolver: configCategory,
                    exclusion: shouldExcludeConfig
                ))
            }
        }

        return uniqueSorted(files)
    }

    private static func discoverPolicyFiles() -> [ManagedTextFile] {
        var files: [ManagedTextFile] = []
        let home = FileManager.default.homeDirectoryForCurrentUser
        let runtimePolicyDir = home
            .appendingPathComponent(".defenseclaw", isDirectory: true)
            .appendingPathComponent("policies", isDirectory: true)

        files.append(contentsOf: scanDirectory(
            runtimePolicyDir,
            source: .runtime,
            base: home,
            categoryResolver: policyCategory,
            exclusion: shouldExcludePolicy
        ))

        if let resources = Bundle.main.resourceURL {
            files.append(contentsOf: scanDirectory(
                resources.appendingPathComponent("policies", isDirectory: true),
                source: .bundled,
                base: resources,
                categoryResolver: policyCategory,
                exclusion: shouldExcludePolicy,
                isEditable: false
            ))
        }

        if let root = projectRoot() {
            files.append(contentsOf: scanDirectory(
                root.appendingPathComponent("policies", isDirectory: true),
                source: .project,
                base: root,
                categoryResolver: policyCategory,
                exclusion: shouldExcludePolicy
            ))
        }

        return uniqueSorted(files)
    }

    private static func appendIfPresent(
        _ url: URL,
        to files: inout [ManagedTextFile],
        category: String,
        group: String,
        source: ManagedTextFileSource,
        base: URL
    ) {
        guard FileManager.default.fileExists(atPath: url.path),
              isSupportedEditableFile(url),
              !shouldExcludeConfig(url) else {
            return
        }

        files.append(ManagedTextFile(
            url: url,
            relativePath: relativePath(for: url, base: base),
            category: category,
            group: group,
            source: source
        ))
    }

    private static func scanDirectory(
        _ directory: URL,
        source: ManagedTextFileSource,
        base: URL,
        categoryResolver: (URL) -> (category: String, group: String),
        exclusion: (URL) -> Bool,
        isEditable: Bool = true
    ) -> [ManagedTextFile] {
        guard FileManager.default.fileExists(atPath: directory.path) else {
            return []
        }

        guard let enumerator = FileManager.default.enumerator(
            at: directory,
            includingPropertiesForKeys: [.isRegularFileKey, .fileSizeKey],
            options: [.skipsPackageDescendants]
        ) else {
            return []
        }

        var files: [ManagedTextFile] = []
        for case let url as URL in enumerator {
            if exclusion(url) {
                if isDirectory(url) {
                    enumerator.skipDescendants()
                }
                continue
            }

            guard isSupportedEditableFile(url),
                  isSmallEnough(url),
                  isRegularFile(url) else {
                continue
            }

            let resolved = categoryResolver(url)
            files.append(ManagedTextFile(
                url: url,
                relativePath: relativePath(for: url, base: base),
                category: resolved.category,
                group: resolved.group,
                source: source,
                isEditable: isEditable
            ))
        }

        return files
    }

    private static func configCategory(for url: URL) -> (category: String, group: String) {
        let path = url.path.lowercased()
        let fileName = url.lastPathComponent.lowercased()

        if path.contains("/.openclaw/") {
            return ("Coding Agents", "OpenClaw")
        }
        if fileName == "config.yaml" || fileName == "config.yml" {
            return ("Primary Config", "DefenseClaw")
        }
        if path.contains("litellm") || path.contains("model") {
            return ("LLM Routing", "Models")
        }
        if path.contains("guardrail") {
            return ("Guardrail", "Runtime")
        }
        if path.contains("splunk") || path.contains("otel") || path.contains("prometheus") || path.contains("grafana") || path.contains("loki") || path.contains("tempo") {
            return ("Observability", "Bundles")
        }
        if path.contains("/policies/scanners/") {
            return ("Scanner Policy Config", "Policies")
        }
        if path.contains("plugin") || path.contains("mcp") || path.contains("skill") {
            return ("Inventory Sources", "Runtime")
        }

        return ("Other Config", "Files")
    }

    private static func policyCategory(for url: URL) -> (category: String, group: String) {
        let path = url.path.lowercased()
        let fileName = url.lastPathComponent.lowercased()

        if path.contains("/rego/") || fileName.hasSuffix(".rego") {
            return ("OPA / Rego", "Policy Engine")
        }
        if path.contains("/guardrail/") {
            return ("Guardrail Rules", "Guardrail")
        }
        if path.contains("/scanners/") {
            return ("Scanner Policies", "Scanners")
        }
        if path.contains("/openshell/") {
            return ("OpenShell Sandbox", "Sandbox")
        }
        if fileName.contains("firewall") {
            return ("Firewall", "Network")
        }

        return ("Policy Templates", "Admission")
    }

    private static func projectRoot() -> URL? {
        guard let override = ProcessInfo.processInfo.environment["DEFENSECLAW_DESKTOP_PROJECT_ROOT"],
              !override.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            return nil
        }

        let candidates = [URL(fileURLWithPath: override)]

        for candidate in candidates {
            if let root = searchUpwardForProjectRoot(from: candidate) {
                return root
            }
        }

        return nil
    }

    private static func searchUpwardForProjectRoot(from start: URL) -> URL? {
        var current = start.hasDirectoryPath ? start : start.deletingLastPathComponent()
        let fileManager = FileManager.default

        while current.path != "/" {
            let configFile = current
                .appendingPathComponent("internal", isDirectory: true)
                .appendingPathComponent("config", isDirectory: true)
                .appendingPathComponent("config.go")
            let policies = current.appendingPathComponent("policies", isDirectory: true)
            if fileManager.fileExists(atPath: configFile.path),
               fileManager.fileExists(atPath: policies.path) {
                return current
            }
            current.deleteLastPathComponent()
        }

        return nil
    }

    private static func isSupportedEditableFile(_ url: URL) -> Bool {
        editableExtensions.contains(url.pathExtension.lowercased())
    }

    private static func isRegularFile(_ url: URL) -> Bool {
        guard let values = try? url.resourceValues(forKeys: [.isRegularFileKey]) else {
            return false
        }
        return values.isRegularFile == true
    }

    private static func isDirectory(_ url: URL) -> Bool {
        guard let values = try? url.resourceValues(forKeys: [.isDirectoryKey]) else {
            return false
        }
        return values.isDirectory == true
    }

    private static func isSmallEnough(_ url: URL) -> Bool {
        guard let size = try? url.resourceValues(forKeys: [.fileSizeKey]).fileSize else {
            return true
        }
        return size <= maxEditableFileBytes
    }

    private static func shouldExcludeConfig(_ url: URL) -> Bool {
        if shouldExcludeCommon(url) {
            return true
        }

        let fileName = url.lastPathComponent.lowercased()
        let sensitiveFileNames: Set<String> = [
            "auth-profiles.json",
            "device-auth.json",
            "credentials.json",
            "credential.json",
            "tokens.json",
            "token.json",
            "paired.json",
            "pending.json"
        ]

        if sensitiveFileNames.contains(fileName) {
            return true
        }

        let path = url.path.lowercased()
        return path.contains("credential")
            || path.contains("secret")
            || path.contains("token")
            || path.contains("auth")
            || path.contains("/identity/")
            || path.contains("oauth")
            || path.contains("history")
    }

    private static func shouldExcludePolicy(_ url: URL) -> Bool {
        if shouldExcludeCommon(url) {
            return true
        }

        let path = url.path.lowercased()
        return path.contains("credential")
            || path.contains("/tokens/")
            || path.contains("/auth/")
            || path.contains("/oauth/")
            || path.contains("history")
    }

    private static func shouldExcludeCommon(_ url: URL) -> Bool {
        let components = url.path
            .lowercased()
            .split(separator: "/")
            .map(String.init)

        let excludedComponents: Set<String> = [
            ".git",
            ".venv",
            "__pycache__",
            "node_modules",
            "site-packages",
            "quarantine",
            "sessions",
            "credentials",
            "tokens",
            "cache",
            "logs"
        ]

        if components.contains(where: { excludedComponents.contains($0) }) {
            return true
        }

        let path = url.path.lowercased()
        return path.hasSuffix("package-lock.json")
    }

    private static func relativePath(for url: URL, base: URL) -> String {
        let path = url.standardizedFileURL.path
        let basePath = base.standardizedFileURL.path

        if path == basePath {
            return url.lastPathComponent
        }
        if path.hasPrefix(basePath + "/") {
            return String(path.dropFirst(basePath.count + 1))
        }

        let home = FileManager.default.homeDirectoryForCurrentUser.standardizedFileURL.path
        if path.hasPrefix(home + "/") {
            return "~/" + String(path.dropFirst(home.count + 1))
        }

        return path
    }

    private static func uniqueSorted(_ files: [ManagedTextFile]) -> [ManagedTextFile] {
        var seen = Set<String>()
        return files
            .filter { file in
                if seen.contains(file.url.standardizedFileURL.path) {
                    return false
                }
                seen.insert(file.url.standardizedFileURL.path)
                return true
            }
            .sorted {
                let leftRank = categorySortRank($0.category)
                let rightRank = categorySortRank($1.category)
                if leftRank != rightRank {
                    return leftRank < rightRank
                }
                if $0.category != $1.category {
                    return $0.category < $1.category
                }
                if $0.source.rawValue != $1.source.rawValue {
                    return sourceSortRank($0.source) < sourceSortRank($1.source)
                }
                return $0.relativePath < $1.relativePath
            }
    }

    private static func categorySortRank(_ category: String) -> Int {
        switch category {
        case "Primary Config":
            return 0
        case "Guardrail":
            return 1
        case "Guardrail Runtime":
            return 2
        case "LLM Routing":
            return 3
        case "Coding Agents":
            return 4
        case "Scanner Policy Config":
            return 5
        case "Observability":
            return 6
        case "Inventory Sources":
            return 7
        case "Firewall":
            return 10
        case "Guardrail Rules":
            return 11
        case "OPA / Rego":
            return 12
        case "OpenShell Sandbox":
            return 13
        case "Scanner Policies":
            return 14
        case "Policy Templates":
            return 15
        default:
            return 100
        }
    }

    private static func sourceSortRank(_ source: ManagedTextFileSource) -> Int {
        switch source {
        case .runtime:
            return 0
        case .openClaw:
            return 1
        case .project:
            return 2
        case .bundled:
            return 3
        }
    }

    private static func validateRegoBasics(_ content: String) -> ManagedFileValidation {
        guard content.contains("package ") else {
            return .invalid("Rego policy is missing a package declaration")
        }

        var braceDepth = 0
        for character in content {
            if character == "{" {
                braceDepth += 1
            } else if character == "}" {
                braceDepth -= 1
                if braceDepth < 0 {
                    return .invalid("Rego braces are unbalanced")
                }
            }
        }

        if braceDepth != 0 {
            return .invalid("Rego braces are unbalanced")
        }

        return .valid("Basic Rego checks passed")
    }
}

enum TextFileWorkspaceError: LocalizedError {
    case readOnly(String)

    var errorDescription: String? {
        switch self {
        case .readOnly(let path):
            return "\(path) is read-only"
        }
    }
}
