import Foundation
import Yams

public struct ConfigManager: Sendable {
    private let configPath: String

    public init(configPath: String? = nil) {
        if let path = configPath {
            self.configPath = path
        } else {
            let home = FileManager.default.homeDirectoryForCurrentUser.path
            self.configPath = "\(home)/.defenseclaw/config.yaml"
        }
    }

    public func load() throws -> AppConfig {
        let url = URL(fileURLWithPath: configPath)
        let data = try Data(contentsOf: url)
        let yaml = String(data: data, encoding: .utf8) ?? ""
        let decoder = YAMLDecoder()
        return try decoder.decode(AppConfig.self, from: yaml)
    }

    public func save(_ config: AppConfig) throws {
        let encoder = YAMLEncoder()
        let yaml = try encoder.encode(config)
        let url = URL(fileURLWithPath: configPath)
        let dir = url.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        try yaml.write(to: url, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: configPath)
    }

    public var exists: Bool {
        FileManager.default.fileExists(atPath: configPath)
    }

    /// Ensures ~/.defenseclaw/ directory and default config.yaml exist.
    /// Safe to call multiple times — only writes if config is missing.
    public func ensureInitialized() throws {
        let url = URL(fileURLWithPath: configPath)
        let dir = url.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)

        // Create subdirectories the sidecar expects
        let dataDir = dir.path
        for sub in ["quarantine", "plugins", "policies", "codeguard-rules"] {
            let subDir = URL(fileURLWithPath: dataDir).appendingPathComponent(sub)
            try FileManager.default.createDirectory(at: subDir, withIntermediateDirectories: true)
        }

        // Write default config if none exists
        if !exists {
            let defaultConfig = AppConfig()
            try save(defaultConfig)
        }
    }
}
