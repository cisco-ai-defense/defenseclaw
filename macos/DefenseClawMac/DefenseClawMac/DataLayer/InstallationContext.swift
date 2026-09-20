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

enum InstallationSource: String, Sendable, Equatable {
    case environmentConfig
    case appOverride
    case environmentHome
    case managedPackage
    case userDefault

    var label: String {
        switch self {
        case .environmentConfig: "DEFENSECLAW_CONFIG"
        case .appOverride: "Mac app override"
        case .environmentHome: "DEFENSECLAW_HOME"
        case .managedPackage: "Cisco managed installation"
        case .userDefault: "User default"
        }
    }
}

enum InstallationAccessMode: Sendable, Equatable {
    case unmanagedMutable
    case managedReadOnly(String)
    case invalidReadOnly(String)

    var permitsMutation: Bool {
        if case .unmanagedMutable = self { return true }
        return false
    }

    var label: String {
        switch self {
        case .unmanagedMutable: "Unmanaged — setup changes allowed"
        case .managedReadOnly: "Managed enterprise — read only"
        case .invalidReadOnly: "Invalid installation selection — read only"
        }
    }

    var reason: String? {
        switch self {
        case .unmanagedMutable: nil
        case .managedReadOnly(let reason), .invalidReadOnly(let reason): reason
        }
    }
}

/// One coherent DefenseClaw installation selected for every filesystem,
/// subprocess, and gateway operation in the Mac app. Resolution intentionally
/// does not evaluate symlinks: the gateway/CLI trust checks must still see and
/// reject a forbidden final-component symlink rather than having the GUI hide
/// it first.
struct InstallationContext: Sendable, Equatable {
    static let configPathOverrideKey = "defenseclawConfigPath"

    static let managedRootPath = "/opt/cisco/secureclient/defenseclaw"
    static let managedConfigPath = managedRootPath + "/etc/config.yaml"
    static let managedRuntimePath = managedRootPath + "/runtime"
    static let managedGatewayPath = managedRootPath + "/bin/defenseclaw-gateway"
    static let managedLogDirectoryPath = "/Library/Logs/Cisco/SecureClient/DefenseClaw"
    static let managedLaunchdPlistPath = "/Library/LaunchDaemons/com.cisco.secureclient.defenseclaw.plist"

    let source: InstallationSource
    let accessMode: InstallationAccessMode
    /// DEFENSECLAW_HOME semantics. This is deliberately distinct from the
    /// config's effective data_dir and from the current macOS user's home.
    let homeRoot: URL
    let configURL: URL
    let dataDirectory: URL
    let auditDBURL: URL
    let environmentURL: URL
    let gatewayJSONLURL: URL
    let gatewayLogURL: URL
    let gatewayErrorLogURL: URL?
    let watchdogLogURL: URL
    let venvURL: URL

    var runtimePythonURL: URL {
        venvURL.appendingPathComponent("bin/python", isDirectory: false)
    }

    var runtimeCLIURL: URL {
        venvURL.appendingPathComponent("bin/defenseclaw", isDirectory: false)
    }

    var permitsMutation: Bool { accessMode.permitsMutation }

    func hasSamePaths(as other: InstallationContext) -> Bool {
        homeRoot == other.homeRoot
            && configURL == other.configURL
            && dataDirectory == other.dataDirectory
            && auditDBURL == other.auditDBURL
            && environmentURL == other.environmentURL
            && gatewayJSONLURL == other.gatewayJSONLURL
            && gatewayLogURL == other.gatewayLogURL
            && gatewayErrorLogURL == other.gatewayErrorLogURL
            && watchdogLogURL == other.watchdogLogURL
            && venvURL == other.venvURL
    }

    func reducingToInvalidReadOnly(_ reason: String) -> InstallationContext {
        guard permitsMutation else { return self }
        return InstallationContext(
            source: source,
            accessMode: .invalidReadOnly(reason),
            homeRoot: homeRoot,
            configURL: configURL,
            dataDirectory: dataDirectory,
            auditDBURL: auditDBURL,
            environmentURL: environmentURL,
            gatewayJSONLURL: gatewayJSONLURL,
            gatewayLogURL: gatewayLogURL,
            gatewayErrorLogURL: gatewayErrorLogURL,
            watchdogLogURL: watchdogLogURL,
            venvURL: venvURL
        )
    }

    /// Environment keys that define installation identity. Call-specific
    /// environment values are merged first and these values are applied last,
    /// preventing a wizard or catalog action from crossing installations.
    var protectedSubprocessEnvironment: [String: String] {
        var values = [
            "DEFENSECLAW_HOME": homeRoot.path,
            "DEFENSECLAW_CONFIG": configURL.path,
            "DEFENSECLAW_VENV": venvURL.path,
        ]
        if case .managedReadOnly = accessMode {
            values["DEFENSECLAW_DEPLOYMENT_MODE"] = "managed_enterprise"
        }
        return values
    }

    var diskSignature: String {
        [configURL, environmentURL].map { url in
            let attributes = try? FileManager.default.attributesOfItem(atPath: url.path)
            let modified = (attributes?[.modificationDate] as? Date)?.timeIntervalSince1970 ?? 0
            let size = (attributes?[.size] as? NSNumber)?.int64Value ?? 0
            return "\(url.path):\(modified):\(size)"
        }.joined(separator: "|")
    }

    static func resolve(
        environment: [String: String] = ProcessInfo.processInfo.environment,
        appConfigOverride: String? = UserDefaults.standard.string(forKey: configPathOverrideKey),
        userHome: URL = FileManager.default.homeDirectoryForCurrentUser,
        currentDirectory: URL = URL(fileURLWithPath: FileManager.default.currentDirectoryPath, isDirectory: true),
        fileExists: (String) -> Bool = { FileManager.default.fileExists(atPath: $0) },
        readText: (URL) -> String? = { try? String(contentsOf: $0, encoding: .utf8) }
    ) -> InstallationContext {
        let defaultHome = userHome.appendingPathComponent(".defenseclaw", isDirectory: true)
        let managedRoot = URL(fileURLWithPath: managedRootPath, isDirectory: true)
        let managedConfig = URL(fileURLWithPath: managedConfigPath, isDirectory: false)
        let managedPackageEvidence = fileExists(managedConfigPath) || fileExists(managedLaunchdPlistPath)

        let environmentConfig = nonBlank(environment["DEFENSECLAW_CONFIG"])
        let appOverride = nonBlank(appConfigOverride)
        let environmentHome = nonBlank(environment["DEFENSECLAW_HOME"])
        let environmentVenv = nonBlank(environment["DEFENSECLAW_VENV"])

        var source: InstallationSource
        var configURL: URL
        var homeRoot: URL
        var invalidReason: String?

        if let raw = environmentConfig {
            source = .environmentConfig
            if let absolute = absoluteOverride(raw) {
                configURL = absolute
            } else {
                invalidReason = "DEFENSECLAW_CONFIG must be an absolute path."
                configURL = absolutePath(raw, userHome: userHome, currentDirectory: currentDirectory)
            }
            homeRoot = defaultHome
        } else if let raw = appOverride {
            source = .appOverride
            if let absolute = absoluteOverride(raw) {
                configURL = absolute
            } else {
                invalidReason = "The Mac app config override must be an absolute path."
                configURL = absolutePath(raw, userHome: userHome, currentDirectory: currentDirectory)
            }
            homeRoot = defaultHome
        } else if let raw = environmentHome {
            source = .environmentHome
            if let absolute = absoluteOverride(raw) {
                homeRoot = absolute
            } else {
                invalidReason = "DEFENSECLAW_HOME must be an absolute path."
                homeRoot = absolutePath(raw, userHome: userHome, currentDirectory: currentDirectory)
            }
            configURL = homeRoot.appendingPathComponent("config.yaml", isDirectory: false)
        } else if managedPackageEvidence {
            source = .managedPackage
            homeRoot = managedRoot
            configURL = managedConfig
        } else {
            source = .userDefault
            homeRoot = defaultHome
            configURL = defaultHome.appendingPathComponent("config.yaml", isDirectory: false)
        }

        // CONFIG/app override outranks HOME for source selection, but HOME
        // still supplies Go/Python's default runtime root when it is valid.
        if source == .environmentConfig || source == .appOverride, let raw = environmentHome {
            if let absolute = absoluteOverride(raw) {
                homeRoot = absolute
            } else if invalidReason == nil {
                invalidReason = "DEFENSECLAW_HOME must be an absolute path."
            }
        }

        let selectedPackagedConfig = configURL.standardizedFileURL.path
            == managedConfig.standardizedFileURL.path
        if selectedPackagedConfig, environmentHome == nil {
            homeRoot = managedRoot
        }

        var venvURL = source == .managedPackage || selectedPackagedConfig
            ? URL(fileURLWithPath: managedRuntimePath, isDirectory: true)
                .appendingPathComponent(".venv", isDirectory: true)
            : homeRoot.appendingPathComponent(".venv", isDirectory: true)
        if let raw = environmentVenv {
            if let absolute = absoluteOverride(raw) {
                venvURL = absolute
            } else if invalidReason == nil {
                invalidReason = "DEFENSECLAW_VENV must be an absolute path."
            }
        }

        let text = readText(configURL)
        if source == .environmentConfig || source == .appOverride {
            if !fileExists(configURL.path) {
                invalidReason = invalidReason ?? "The explicitly selected config.yaml does not exist."
            } else if text == nil {
                invalidReason = invalidReason ?? "The explicitly selected config.yaml could not be read."
            }
        }
        let root = text.map(MiniYAML.parse)
        if text != nil, root?.mapping == nil {
            invalidReason = invalidReason ?? "config.yaml must contain a top-level mapping."
        }
        if let deploymentNode = root?["deployment_mode"], deploymentNode.string == nil {
            invalidReason = invalidReason ?? "config.yaml deployment_mode must be a string."
        }
        if let dataDirectoryNode = root?["data_dir"], dataDirectoryNode.string == nil {
            invalidReason = invalidReason ?? "config.yaml data_dir must be a string."
        }
        if let observabilityNode = root?["observability"], observabilityNode.mapping == nil {
            invalidReason = invalidReason ?? "config.yaml observability must be a mapping."
        }
        if let localNode = root?["observability.local"], localNode.mapping == nil {
            invalidReason = invalidReason ?? "config.yaml observability.local must be a mapping."
        }
        if let auditPathNode = root?["observability.local.path"], auditPathNode.string == nil {
            invalidReason = invalidReason
                ?? "config.yaml observability.local.path must be a string."
        }
        let configuredDataDirectory = nonBlank(root?["data_dir"]?.string)
        let configuredAuditPath = nonBlank(
            root?["observability.local.path"]?.string ?? root?["audit_db"]?.string
        )
        if let configuredDataDirectory, !configuredDataDirectory.hasPrefix("/") {
            invalidReason = invalidReason ?? "config.yaml data_dir must be an absolute path."
        }
        if let configuredAuditPath, !configuredAuditPath.hasPrefix("/") {
            invalidReason = invalidReason
                ?? "config.yaml observability.local.path must be an absolute path."
        }
        let rawConfigMode = nonBlank(root?["deployment_mode"]?.string)
        let configMode = normalizedDeploymentMode(rawConfigMode)
        let pinnedMode = normalizedDeploymentMode(nonBlank(environment["DEFENSECLAW_DEPLOYMENT_MODE"]))
        if let rawConfigMode, configMode == nil {
            invalidReason = invalidReason
                ?? "config.yaml deployment_mode has an unsupported value: \(rawConfigMode)."
        }
        if let rawPinned = nonBlank(environment["DEFENSECLAW_DEPLOYMENT_MODE"]), pinnedMode == nil {
            invalidReason = invalidReason ?? "DEFENSECLAW_DEPLOYMENT_MODE has an unsupported value: \(rawPinned)."
        }
        if let pinnedMode, let configMode, pinnedMode != configMode {
            invalidReason = invalidReason
                ?? "DEFENSECLAW_DEPLOYMENT_MODE conflicts with config.yaml deployment_mode."
        }

        let selectedManagedPath = selectedPackagedConfig
        if managedPackageEvidence, source != .managedPackage, !selectedManagedPath {
            if configMode != "managed_enterprise" || (pinnedMode != nil && pinnedMode != "managed_enterprise") {
                invalidReason = invalidReason
                    ?? "A Cisco managed installation is present and conflicts with the selected non-managed config."
            }
        }
        let managed = source == .managedPackage
            || selectedManagedPath
            || managedPackageEvidence
            || pinnedMode == "managed_enterprise"
            || configMode == "managed_enterprise"

        let accessMode: InstallationAccessMode
        if let invalidReason {
            accessMode = .invalidReadOnly(invalidReason)
        } else if managed {
            let reason = text == nil && (source == .managedPackage || selectedManagedPath)
                ? "The administrator-owned managed config is unavailable; writes remain disabled."
                : "This installation is administrator managed. Use enterprise deployment tooling to change it."
            accessMode = .managedReadOnly(reason)
        } else {
            accessMode = .unmanagedMutable
        }

        let packagedManaged = source == .managedPackage || selectedPackagedConfig
        let defaultDataDirectory = packagedManaged ? URL(
            fileURLWithPath: managedRuntimePath,
            isDirectory: true
        ) : homeRoot
        let dataDirectory = configuredURL(
            configuredDataDirectory?.hasPrefix("/") == true ? configuredDataDirectory : nil,
            fallback: defaultDataDirectory,
            userHome: userHome,
            currentDirectory: currentDirectory,
            isDirectory: true
        )
        let auditDBURL = configuredURL(
            configuredAuditPath?.hasPrefix("/") == true ? configuredAuditPath : nil,
            fallback: dataDirectory.appendingPathComponent("audit.db", isDirectory: false),
            userHome: userHome,
            currentDirectory: currentDirectory,
            isDirectory: false
        )

        let logDirectory = packagedManaged
            ? URL(fileURLWithPath: managedLogDirectoryPath, isDirectory: true)
            : dataDirectory

        return InstallationContext(
            source: source,
            accessMode: accessMode,
            homeRoot: homeRoot.standardizedFileURL,
            configURL: configURL.standardizedFileURL,
            dataDirectory: dataDirectory,
            auditDBURL: auditDBURL,
            environmentURL: dataDirectory.appendingPathComponent(".env", isDirectory: false),
            gatewayJSONLURL: dataDirectory.appendingPathComponent("gateway.jsonl", isDirectory: false),
            gatewayLogURL: logDirectory.appendingPathComponent("gateway.log", isDirectory: false),
            gatewayErrorLogURL: packagedManaged
                ? logDirectory.appendingPathComponent("gateway.err.log", isDirectory: false)
                : nil,
            watchdogLogURL: logDirectory.appendingPathComponent("watchdog.log", isDirectory: false),
            venvURL: venvURL.standardizedFileURL
        )
    }

    private static func nonBlank(_ value: String?) -> String? {
        guard let value = value?.trimmingCharacters(in: .whitespacesAndNewlines), !value.isEmpty else {
            return nil
        }
        return value
    }

    private static func absoluteOverride(_ raw: String) -> URL? {
        guard raw.hasPrefix("/") else { return nil }
        return URL(fileURLWithPath: raw).standardizedFileURL
    }

    private static func configuredURL(
        _ raw: String?,
        fallback: URL,
        userHome: URL,
        currentDirectory: URL,
        isDirectory: Bool
    ) -> URL {
        guard let raw = nonBlank(raw) else { return fallback.standardizedFileURL }
        let resolved = absolutePath(raw, userHome: userHome, currentDirectory: currentDirectory)
        return URL(fileURLWithPath: resolved.path, isDirectory: isDirectory).standardizedFileURL
    }

    private static func absolutePath(_ raw: String, userHome: URL, currentDirectory: URL) -> URL {
        if raw == "~" { return userHome.standardizedFileURL }
        if raw.hasPrefix("~/") {
            return userHome.appendingPathComponent(String(raw.dropFirst(2))).standardizedFileURL
        }
        if raw.hasPrefix("/") { return URL(fileURLWithPath: raw).standardizedFileURL }
        return currentDirectory.appendingPathComponent(raw).standardizedFileURL
    }

    private static func normalizedDeploymentMode(_ raw: String?) -> String? {
        guard let value = nonBlank(raw)?.lowercased() else { return nil }
        switch value {
        case "managed", "managed_enterprise": return "managed_enterprise"
        case "standalone", "unmanaged_byod": return "unmanaged_byod"
        case "ci", "ci_cd": return "ci_cd"
        case "edge": return "server"
        case "sandboxed", "server", "saas": return value
        default: return nil
        }
    }
}
