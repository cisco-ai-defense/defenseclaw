import Foundation
import Yams

struct YAMLConfigStore {
    private(set) var url: URL
    private(set) var document: [String: Any] = [:]

    init(url: URL = YAMLConfigStore.defaultConfigURL()) {
        self.url = url
    }

    mutating func load() throws {
        guard FileManager.default.fileExists(atPath: url.path) else {
            document = [:]
            return
        }

        let content = try String(contentsOf: url, encoding: .utf8)
        guard !content.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            document = [:]
            return
        }

        let loaded = try Yams.load(yaml: content)
        document = loaded as? [String: Any] ?? [:]
    }

    func value(at path: String) -> Any? {
        let keys = split(path)
        guard !keys.isEmpty else {
            return nil
        }

        var current: Any? = document
        for key in keys {
            guard let dict = current as? [String: Any] else {
                return nil
            }
            current = dict[key]
        }
        return current
    }

    func string(at path: String) -> String {
        guard let value = value(at: path) else {
            return ""
        }

        switch value {
        case let string as String:
            return string
        case let bool as Bool:
            return bool ? "true" : "false"
        case let int as Int:
            return String(int)
        case let double as Double:
            return String(double)
        case let array as [Any]:
            return array.map { String(describing: $0) }.joined(separator: ",")
        default:
            return String(describing: value)
        }
    }

    func bool(at path: String) -> Bool {
        guard let value = value(at: path) else {
            return false
        }

        switch value {
        case let bool as Bool:
            return bool
        case let string as String:
            return ["true", "yes", "1", "on"].contains(string.trimmingCharacters(in: .whitespacesAndNewlines).lowercased())
        case let int as Int:
            return int != 0
        default:
            return false
        }
    }

    mutating func set(_ value: Any?, at path: String) {
        let keys = split(path)
        guard !keys.isEmpty else {
            return
        }

        set(value, for: ArraySlice(keys), in: &document)
    }

    mutating func save() throws {
        let directory = url.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let yaml = try Yams.dump(object: document, sortKeys: false)
        try yaml.write(to: url, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }

    static func defaultConfigURL() -> URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".defenseclaw", isDirectory: true)
            .appendingPathComponent("config.yaml")
    }

    private func split(_ path: String) -> [String] {
        path
            .split(separator: ".")
            .map(String.init)
            .filter { !$0.isEmpty }
    }

    private func set(_ value: Any?, for keys: ArraySlice<String>, in dict: inout [String: Any]) {
        guard let key = keys.first else {
            return
        }

        if keys.count == 1 {
            if let value {
                dict[key] = value
            } else {
                dict.removeValue(forKey: key)
            }
            return
        }

        var child = dict[key] as? [String: Any] ?? [:]
        set(value, for: keys.dropFirst(), in: &child)
        dict[key] = child
    }
}
