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
import Observation

enum CommandActivityStatus: String, Sendable {
    case running
    case succeeded
    case failed
    case cancelled
}

struct CommandActivityEntry: Identifiable, Sendable {
    let id: UUID
    var title: String
    var command: String
    var category: String
    var origin: String
    var startedAt: Date
    var finishedAt: Date?
    var exitCode: Int32?
    var status: CommandActivityStatus
    var output: String
    var sideEffects: [String]
    var suggestedNextAction: String

    var duration: TimeInterval {
        (finishedAt ?? Date()).timeIntervalSince(startedAt)
    }

    var statusLabel: String {
        switch status {
        case .running: "Running"
        case .succeeded: "Exit 0"
        case .failed: "Exit \(exitCode ?? -1)"
        case .cancelled: "Cancelled"
        }
    }
}

@Observable
@MainActor
final class CommandActivityStore {
    private static let maximumOutputCharacters = 300_000
    private static let maximumEntries = 500
    private static let omittedPrefix = "[Earlier output omitted]\n"

    @ObservationIgnored private let runner: CLIRunner
    var entries: [CommandActivityEntry] = []
    var selectedID: UUID?

    init(runner: CLIRunner) {
        self.runner = runner
    }

    @discardableResult
    func run(
        id: UUID = UUID(),
        title: String,
        binary: String = "defenseclaw",
        arguments: [String],
        standardInput: String? = nil,
        environment: [String: String] = [:],
        mutation: Bool = true,
        category: String = "other",
        origin: String,
        successEffects: [String] = [],
        suggestedNextAction: String = ""
    ) async -> CLIResult {
        entries.insert(
            CommandActivityEntry(
                id: id,
                title: title,
                command: Self.displayCommand(
                    binary: binary,
                    arguments: arguments,
                    maskedEnvironmentKeys: environment.keys.sorted()
                ),
                category: category,
                origin: origin,
                startedAt: Date(),
                status: .running,
                output: "",
                sideEffects: [],
                suggestedNextAction: ""
            ),
            at: 0
        )
        selectedID = id
        while entries.count > Self.maximumEntries,
              let removable = entries.lastIndex(where: { $0.status != .running }) {
            entries.remove(at: removable)
        }

        let result = await runner.run(
            binary: binary,
            arguments: arguments,
            standardInput: standardInput,
            environment: environment,
            mutation: mutation,
            runID: id
        ) { [weak self] line in
            await self?.append(line: line, to: id)
        }

        guard let index = entries.firstIndex(where: { $0.id == id }) else { return result }
        if entries[index].output.isEmpty { entries[index].output = result.output }
        entries[index].finishedAt = Date()
        entries[index].exitCode = result.exitCode
        entries[index].status = result.cancelled ? .cancelled : (result.succeeded ? .succeeded : .failed)
        if result.succeeded {
            entries[index].sideEffects = successEffects.isEmpty
                ? Self.inferredEffects(binary: binary, arguments: arguments, category: category)
                : successEffects
        }
        entries[index].suggestedNextAction = result.succeeded ? suggestedNextAction : "Review the output, then run DefenseClaw Doctor."
        return result
    }

    func cancel(_ id: UUID) {
        Task { await runner.cancel(runID: id) }
    }

    func clearCompleted() {
        entries.removeAll { $0.status != .running }
        if let selectedID, !entries.contains(where: { $0.id == selectedID }) {
            self.selectedID = entries.first?.id
        }
    }

    private func append(line: String, to id: UUID) {
        guard let index = entries.firstIndex(where: { $0.id == id }) else { return }
        entries[index].output += line + "\n"
        if entries[index].output.count > Self.maximumOutputCharacters {
            let available = Self.maximumOutputCharacters - Self.omittedPrefix.count
            entries[index].output = Self.omittedPrefix + entries[index].output.suffix(max(available, 0))
        }
    }

    private static func displayCommand(
        binary: String,
        arguments: [String],
        maskedEnvironmentKeys: [String] = []
    ) -> String {
        let environment = maskedEnvironmentKeys.map { "\($0)=••••••" }
        return (environment + [binary] + arguments).map(ShellQuoting.quote).joined(separator: " ")
    }

    private static func inferredEffects(binary: String, arguments: [String], category: String) -> [String] {
        guard let command = arguments.first else { return [] }
        if binary == "defenseclaw-gateway" {
            if command == "restart" { return ["Gateway restarted"] }
            if command == "start" { return ["Gateway started"] }
            if command == "stop" { return ["Gateway stopped"] }
        }
        if command == "init" { return ["Configuration initialized"] }
        if command == "setup" || command == "config" { return ["Configuration updated"] }
        if command == "doctor" { return ["Diagnostic results refreshed"] }
        if command == "aibom" || category == "scan" { return ["Inventory or scan data refreshed"] }
        if command == "alerts" { return ["Alert state updated"] }
        if ["skill", "mcp", "plugin", "registry", "registries", "tool"].contains(command), category != "info" {
            return ["\(command.capitalized) state updated"]
        }
        return category == "info" ? [] : ["DefenseClaw state updated"]
    }
}
