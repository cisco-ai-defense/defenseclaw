// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

import Foundation

enum RegistryStore {
    static func load(config: DefenseClawConfig) -> RegistrySnapshot {
        load(sources: config.registrySources, dataDirectory: dataDirectory(for: config))
    }

    static func load(
        sources: [DefenseClawConfig.RegistrySourceConfig],
        dataDirectory: URL
    ) -> RegistrySnapshot {
        var loadedSources: [RegistrySource] = []
        var loadedEntries: [RegistryEntry] = []

        for sourceConfig in sources.sorted(by: { $0.id.localizedStandardCompare($1.id) == .orderedAscending }) {
            var source = RegistrySource(
                id: sourceConfig.id,
                kind: sourceConfig.kind,
                content: sourceConfig.content,
                url: sourceConfig.url,
                authEnv: sourceConfig.authEnv,
                enabled: sourceConfig.enabled,
                autoSync: sourceConfig.autoSync,
                syncIntervalHours: sourceConfig.syncIntervalHours,
                lastSync: sourceConfig.lastSync,
                lastStatus: sourceConfig.lastStatus
            )

            do {
                let cacheURL = try indexURL(dataDirectory: dataDirectory, sourceID: source.id)
                if FileManager.default.fileExists(atPath: cacheURL.path) {
                    let index = try decodeIndex(data: Data(contentsOf: cacheURL), sourceID: source.id)
                    source.fetchedAt = index.fetchedAt
                    source.publisher = index.publisher
                    source.entryCount = index.entryCount
                    source.cleanCount = index.cleanCount
                    source.warningCount = index.warningCount
                    source.blockedCount = index.blockedCount
                    source.errorCount = index.errorCount
                    loadedEntries.append(contentsOf: index.entries)
                }
            } catch {
                source.indexError = error.localizedDescription
            }

            loadedSources.append(source)
        }

        loadedEntries.sort {
            ($0.sourceID, $0.type, $0.name) < ($1.sourceID, $1.type, $1.name)
        }
        return RegistrySnapshot(sources: loadedSources, entries: loadedEntries)
    }

    static func dataDirectory(for config: DefenseClawConfig) -> URL {
        guard let configured = config.dataDir?.trimmingCharacters(in: .whitespacesAndNewlines),
              !configured.isEmpty
        else { return ConfigStore.dataDirectory }

        let expanded = (configured as NSString).expandingTildeInPath
        return URL(fileURLWithPath: expanded, isDirectory: true).standardizedFileURL
    }

    static func indexURL(dataDirectory: URL, sourceID: String) throws -> URL {
        guard isSafeSourceID(sourceID) else {
            throw RegistryStoreError.unsafeSourceID(sourceID)
        }
        return dataDirectory
            .appendingPathComponent("registries", isDirectory: true)
            .appendingPathComponent(sourceID, isDirectory: true)
            .appendingPathComponent("index.json", isDirectory: false)
    }

    static func isSafeSourceID(_ sourceID: String) -> Bool {
        !sourceID.isEmpty && !sourceID.contains { "/\\.".contains($0) }
    }

    static func decodeIndex(data: Data, sourceID: String) throws -> RegistryIndex {
        let raw: Any
        do {
            raw = try JSONSerialization.jsonObject(with: data)
        } catch {
            throw RegistryStoreError.invalidJSON(error.localizedDescription)
        }
        guard let document = raw as? [String: Any] else {
            throw RegistryStoreError.invalidDocument
        }

        let rows = (document["verdicts"] as? [[String: Any]] ?? []).map { row in
            RegistryEntry(
                sourceID: sourceID,
                type: string(row["type"]),
                name: string(row["name"]),
                status: string(row["status"]),
                severity: string(row["severity"]),
                findings: integer(row["findings"]),
                approved: boolean(row["approved"]),
                rejected: boolean(row["rejected"]),
                transport: string(row["transport"]),
                command: string(row["command"]),
                arguments: (row["args"] as? [Any] ?? []).map(string),
                url: string(row["url"]),
                sourceURL: string(row["source_url"])
            )
        }

        return RegistryIndex(
            schemaVersion: integer(document["schema_version"], defaultValue: 1),
            fetchedAt: string(document["fetched_at"]),
            publisher: string(document["publisher"]),
            entryCount: integer(document["entry_count"], defaultValue: rows.count),
            cleanCount: integer(document["clean_count"], defaultValue: rows.filter { $0.status == "clean" }.count),
            warningCount: integer(document["warning_count"], defaultValue: rows.filter { $0.status == "warning" }.count),
            blockedCount: integer(document["blocked_count"], defaultValue: rows.filter { $0.status == "blocked" }.count),
            errorCount: integer(document["error_count"], defaultValue: rows.filter { $0.status == "error" }.count),
            entries: rows
        )
    }

    private static func string(_ value: Any?) -> String {
        guard let value else { return "" }
        if let string = value as? String { return string }
        return String(describing: value)
    }

    private static func integer(_ value: Any?, defaultValue: Int = 0) -> Int {
        if let value = value as? Int { return value }
        if let value = value as? NSNumber { return value.intValue }
        if let value = value as? String, let parsed = Int(value) { return parsed }
        return defaultValue
    }

    private static func boolean(_ value: Any?) -> Bool {
        if let value = value as? Bool { return value }
        if let value = value as? NSNumber { return value.boolValue }
        if let value = value as? String {
            return ["1", "true", "yes", "on"].contains(value.lowercased())
        }
        return false
    }
}

struct RegistryIndex: Sendable {
    var schemaVersion: Int
    var fetchedAt: String
    var publisher: String
    var entryCount: Int
    var cleanCount: Int
    var warningCount: Int
    var blockedCount: Int
    var errorCount: Int
    var entries: [RegistryEntry]
}

enum RegistryStoreError: LocalizedError {
    case unsafeSourceID(String)
    case invalidJSON(String)
    case invalidDocument

    var errorDescription: String? {
        switch self {
        case .unsafeSourceID(let sourceID):
            "Unsafe registry source ID: \(sourceID)"
        case .invalidJSON(let detail):
            "Invalid registry index JSON: \(detail)"
        case .invalidDocument:
            "Registry index must contain a JSON object."
        }
    }
}

enum RegistryCLIArguments {
    static func sync(sourceID: String) -> [String] {
        ["registry", "sync", sourceID, "--json"]
    }

    static let syncAll = ["registry", "sync", "--all", "--json"]

    static func approve(_ entry: RegistryEntry) -> [String] {
        ["registry", "approve", entry.sourceID, entry.name, "--type", entry.type, "--json"]
    }

    static func reject(_ entry: RegistryEntry) -> [String] {
        ["registry", "reject", entry.sourceID, entry.name, "--type", entry.type, "--json"]
    }

    static func setRequired(type: String, required: Bool) -> [String] {
        ["registry", "require", "--type", type, required ? "--enabled" : "--disabled", "--json"]
    }

    static func setSourceEnabled(sourceID: String, enabled: Bool) -> [String] {
        ["registry", "edit", sourceID, enabled ? "--enabled" : "--disabled", "--non-interactive", "--json"]
    }

    static func remove(sourceID: String) -> [String] {
        ["registry", "remove", sourceID, "--non-interactive", "--json"]
    }

    static func add(
        sourceID: String,
        kind: String,
        content: String,
        url: String,
        authEnv: String,
        enabled: Bool
    ) -> [String] {
        var arguments = [
            "registry", "add", sourceID,
            "--kind", kind,
            "--content", content,
        ]
        if !url.isEmpty { arguments += ["--url", url] }
        if !authEnv.isEmpty { arguments += ["--auth-env", authEnv] }
        arguments += [enabled ? "--enabled" : "--disabled", "--non-interactive", "--json"]
        return arguments
    }
}
