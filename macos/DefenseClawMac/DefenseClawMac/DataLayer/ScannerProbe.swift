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

// Overview SCANNERS card — port of the TUI's scanner box (app.py ~5120).
// Six rows: external scanners probed on PATH (skill-scanner, mcp-scanner),
// built-ins that ship in the CLI (aibom, codeguard), the guardrail (state +
// mode/port/rule-pack), and required credentials (keys). All reads are
// filesystem/env only — cheap enough to run on the pulse, no subprocess.
//
// The external scanners ship inside the DefenseClaw install's venv and are
// only usable when linked into a PATH dir (the installer symlinks them into
// ~/.local/bin). When that step was skipped — or an upgrade rebuilt the venv
// and broke the links — the binaries exist but probe as "missing". The probe
// therefore also looks for them next to the resolved `defenseclaw` binary,
// and linkIntoLocalBin() offers a one-click repair that recreates the
// installer's own symlink layout.

import Foundation

struct ScannerStatus: Identifiable, Sendable, Equatable {
    enum Level: Sendable { case active, builtin, warn, missing }
    var name: String
    var detail: String
    var level: Level
    /// Set when the binary exists in the DefenseClaw install but isn't on
    /// PATH: the discovered source path, enabling the one-click Fix.
    var fixSource: String?
    var id: String { name }
}

enum ScannerProbe {
    /// Standard install locations, mirroring the CLI's own search order.
    private static let binDirs: [String] = {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        return ["\(home)/.local/bin", "/opt/homebrew/bin", "/usr/local/bin"]
    }()

    static func binaryInstalled(_ name: String) -> Bool {
        binDirs.contains { FileManager.default.isExecutableFile(atPath: "\($0)/\(name)") }
    }

    private static let openClawGatewayToken = "OPENCLAW_GATEWAY_TOKEN"

    /// Mirrors DefenseClaw credentials._openclaw_gateway_token: the upstream
    /// OpenClaw token is required only when OpenClaw is configured. Legacy
    /// configs without connector information retain the historical OpenClaw
    /// default and therefore still require it.
    static func requiresOpenClawGatewayToken(config: DefenseClawConfig) -> Bool {
        if !config.connectors.isEmpty {
            return config.connectors.contains { normalizedConnector($0) == "openclaw" }
        }

        if let connector = nonEmpty(config.raw["guardrail.connector"]?.string) {
            return normalizedConnector(connector) == "openclaw"
        }

        if let mode = nonEmpty(config.raw["claw.mode"]?.string) {
            return normalizedConnector(mode) == "openclaw"
        }

        return true
    }

    private static func normalizedConnector(_ value: String) -> String {
        value.trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased()
            .replacingOccurrences(of: "-", with: "")
    }

    private static func nonEmpty(_ value: String?) -> String? {
        guard let value = value?.trimmingCharacters(in: .whitespacesAndNewlines),
              !value.isEmpty
        else { return nil }
        return value
    }

    /// Where a scanner binary was found, if anywhere.
    enum Location: Sendable, Equatable {
        case onPath              // executable in a standard bin dir
        case unlinked(String)    // in the DefenseClaw install, not on PATH
        case missing
    }

    /// PATH-dir probe first; otherwise look next to the resolved
    /// `defenseclaw` entry point — the scanners ship in the same venv bin
    /// dir, so a symlink-resolved sibling is the install's own copy.
    /// (isExecutableFile follows symlinks, so a broken ~/.local/bin link
    /// correctly falls through to .unlinked and gets repaired by Fix.)
    static func locate(_ name: String, cliPath: String?) -> Location {
        if binaryInstalled(name) { return .onPath }
        if let cliPath {
            let sibling = URL(fileURLWithPath: cliPath)
                .resolvingSymlinksInPath()
                .deletingLastPathComponent()
                .appendingPathComponent(name).path
            if FileManager.default.isExecutableFile(atPath: sibling) {
                return .unlinked(sibling)
            }
        }
        return .missing
    }

    enum FixError: LocalizedError {
        case destinationOccupied(String)
        case sourceVanished(String)
        var errorDescription: String? {
            switch self {
            case .destinationOccupied(let path):
                "\(path) already exists and is not a symlink — move it aside, then Fix again."
            case .sourceVanished(let path):
                "\(path) is gone — the install moved or was rebuilt; it will re-probe shortly."
            }
        }
    }

    /// One planned symlink for the Fix: absolute source → ~/.local/bin/<target>.
    struct PlannedLink: Sendable, Equatable {
        var target: String
        var source: String
        var destination: String
    }

    /// Plan the one-click repair — pure decision pass, no mutation. The
    /// installer's own layout: symlink the discovered binary into
    /// ~/.local/bin, plus any executable `<name>-*` siblings (…-api,
    /// …-pre-commit) the installer also links. A link that still resolves
    /// to a working executable is left alone — including the probed name
    /// itself: the probe saw it broken, so a now-working link means the
    /// probe data is stale (e.g. a dev install was just restored) and
    /// must not be repointed. A regular file at the destination is never
    /// overwritten. Throws if the probed source itself vanished, so a
    /// stale Fix is never a silent no-op. The caller executes the plan as
    /// recorded `/bin/ln -sfh` steps so the mutation lands in Activity.
    static func linkPlan(name: String, source: String) throws -> [PlannedLink] {
        let fm = FileManager.default
        guard fm.isExecutableFile(atPath: source) else {
            throw FixError.sourceVanished(source)
        }
        let binDir = fm.homeDirectoryForCurrentUser.appendingPathComponent(".local/bin")

        let sourceDir = URL(fileURLWithPath: source).deletingLastPathComponent()
        var targets = [name]
        if let siblings = try? fm.contentsOfDirectory(atPath: sourceDir.path) {
            targets += siblings.filter { $0.hasPrefix("\(name)-") }.sorted()
        }
        var plan: [PlannedLink] = []
        for target in targets {
            let src = sourceDir.appendingPathComponent(target).path
            guard fm.isExecutableFile(atPath: src) else { continue }
            let dest = binDir.appendingPathComponent(target)
            // attributesOfItem does not follow the final symlink (lstat),
            // so a stale link is detected as such rather than as missing.
            if let attrs = try? fm.attributesOfItem(atPath: dest.path) {
                if attrs[.type] as? FileAttributeType == .typeSymbolicLink {
                    // Any link that still works stays untouched — for the
                    // probed name that means the probe went stale between
                    // pulse and click; the post-fix re-probe shows "installed".
                    if fm.isExecutableFile(atPath: dest.path) { continue }
                } else if target == name {
                    throw FixError.destinationOccupied(dest.path)
                } else {
                    continue // never fight over an extra's real file
                }
            }
            // ln -sfh replaces a stale/broken link atomically.
            plan.append(PlannedLink(target: target, source: src, destination: dest.path))
        }
        return plan
    }

    private static func dotEnvNames(environmentURL: URL) -> Set<String> {
        let url = environmentURL
        guard let text = try? String(contentsOf: url, encoding: .utf8) else { return [] }
        var names = Set<String>()
        for rawLine in text.split(separator: "\n") {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            guard !line.isEmpty, !line.hasPrefix("#"), let eq = line.firstIndex(of: "=") else { continue }
            let name = String(line[..<eq]).trimmingCharacters(in: .whitespaces)
            // A name with an empty value doesn't count as set.
            let value = String(line[line.index(after: eq)...])
                .trimmingCharacters(in: .whitespaces)
                .trimmingCharacters(in: CharacterSet(charactersIn: "\"'"))
            if !value.isEmpty {
                names.insert(name)
            }
        }
        return names
    }

    /// Missing required gateway credentials (env or ~/.defenseclaw/.env).
    static func missingKeys(config: DefenseClawConfig, environmentURL: URL) -> [String] {
        let requiredKeys = requiresOpenClawGatewayToken(config: config)
            ? [openClawGatewayToken]
            : []
        let env = ProcessInfo.processInfo.environment
        let dotenv = dotEnvNames(environmentURL: environmentURL)
        return requiredKeys.filter { name in
            let inEnv = !(env[name] ?? "").isEmpty
            return !inEnv && !dotenv.contains(name)
        }
    }

    /// The two external scanners the card probes for.
    static let externalScanners = ["skill-scanner", "mcp-scanner"]

    /// Assemble all six scanner rows. `guardrailState` comes from /health
    /// (e.g. "running"); the mode/port/rule-pack detail comes from config.
    /// `missingCredentials` is the doctor-cache-derived list (TUI keys_status):
    /// nil = no cache yet ("not checked"); [] = all required set.
    /// `cliPath` (the located `defenseclaw` binary) anchors the fallback
    /// search for scanners that exist in the install but aren't on PATH.
    /// `shellFound` holds scanner names an augmented-PATH `which` lookup
    /// resolved (inherited PATH + standard package-manager dirs, checked
    /// once at startup) — binDirs only covers the standard three dirs, so
    /// this keeps a MacPorts/pipx/custom-dir install from being mislabeled
    /// "not in PATH" with a spurious Fix button.
    static func statuses(
        config: DefenseClawConfig,
        guardrailState: String?,
        missingCredentials: [String]? = nil,
        cliPath: String? = nil,
        shellFound: Set<String> = []
    ) -> [ScannerStatus] {
        var rows: [ScannerStatus] = []

        for scanner in externalScanners {
            if shellFound.contains(scanner) {
                rows.append(.init(name: scanner, detail: "installed", level: .active))
                continue
            }
            switch locate(scanner, cliPath: cliPath) {
            case .onPath:
                rows.append(.init(name: scanner, detail: "installed", level: .active))
            case .unlinked(let source):
                rows.append(.init(name: scanner, detail: "found — not in PATH",
                                  level: .warn, fixSource: source))
            case .missing:
                rows.append(.init(name: scanner, detail: "missing", level: .missing))
            }
        }

        rows.append(.init(name: "aibom", detail: "built-in", level: .builtin))
        rows.append(.init(name: "codeguard", detail: "built-in", level: .builtin))

        // guardrail: "<mode>, port <n>, <rulepack>" + running/state.
        let mode = config.guardrailMode ?? "observe"
        let port = config.guardrailPort.map { ", port \($0)" } ?? ""
        let guardrailDetail = "\(mode)\(port), \(config.guardrailRulePack)"
        let running = (guardrailState ?? "").lowercased() == "running"
        rows.append(.init(name: "guardrail", detail: guardrailDetail,
                          level: running ? .active : .warn))

        // keys: required credentials, doctor-cache-driven like the TUI
        // (any failing "credential <NAME>" check counts as missing). NOTE:
        // deliberate deviation — the TUI renders the "N missing" label green
        // (keys.available drives its color); amber is more honest here.
        if let missing = missingCredentials {
            if missing.isEmpty {
                rows.append(.init(name: "keys", detail: "all required set", level: .active))
            } else {
                let preview = missing.prefix(2).joined(separator: ", ")
                let suffix = missing.count > 2 ? " (+\(missing.count - 2) more)" : ""
                rows.append(.init(name: "keys", detail: "\(missing.count) missing: \(preview)\(suffix)",
                                  level: .warn))
            }
        } else {
            // No doctor cache yet (TUI: always "not checked", amber).
            rows.append(.init(name: "keys", detail: "not checked", level: .warn))
        }
        return rows
    }
}
