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

import SwiftUI

struct CommandPaletteView: View {
    @Environment(AppState.self) private var appState
    @Environment(\.dismiss) private var dismiss

    @State private var search = ""
    @State private var category = "all"
    @State private var selectedID: Int? = CommandRegistry.all.first?.id
    @State private var extraArguments = ""
    @State private var output = ""
    @State private var exitCode: Int32?
    @State private var running = false
    @State private var parseError: String?
    @State private var pendingConfirmedRun = false

    private var categories: [String] {
        ["all"] + Array(Set(CommandRegistry.all.map(\.category))).sorted()
    }

    private var filtered: [CommandDefinition] {
        CommandRegistry.all.filter { command in
            let categoryMatches = category == "all" || command.category == category
            let searchMatches = search.isEmpty ||
                "\(command.title) \(command.summary) \(command.category) \(command.usage)"
                    .localizedCaseInsensitiveContains(search)
            return categoryMatches && searchMatches
        }
    }

    private var selected: CommandDefinition? {
        CommandRegistry.all.first { $0.id == selectedID }
    }

    var body: some View {
        NavigationSplitView {
            VStack(spacing: 8) {
                TextField("Search 226 commands", text: $search)
                    .textFieldStyle(.roundedBorder)
                    .padding(.horizontal, 10)
                    .padding(.top, 10)
                Picker("Category", selection: $category) {
                    ForEach(categories, id: \.self) { value in
                        Text(value == "all" ? "All categories" : value.capitalized).tag(value)
                    }
                }
                .labelsHidden()
                .padding(.horizontal, 10)

                List(filtered, selection: $selectedID) { command in
                    VStack(alignment: .leading, spacing: 2) {
                        Text(command.title).font(.callout.weight(.medium)).lineLimit(1)
                        Text(command.summary).font(.caption).foregroundStyle(.secondary).lineLimit(1)
                    }
                    .tag(command.id)
                }
                .listStyle(.sidebar)
                Text("\(filtered.count) of \(CommandRegistry.sourceCount) commands")
                    .font(.caption2).foregroundStyle(.secondary).padding(.bottom, 8)
            }
            .navigationSplitViewColumnWidth(min: 250, ideal: 300)
        } detail: {
            if let command = selected {
                commandDetail(command)
            } else {
                DCEmptyState(title: "Select a command", message: "Search or choose a command from the list.", systemImage: "command")
            }
        }
        .frame(width: 860, height: 580)
        .toolbar {
            ToolbarItem(placement: .confirmationAction) {
                Button("Done") { dismiss() }
            }
        }
        .onChange(of: selectedID) {
            extraArguments = ""
            output = ""
            exitCode = nil
            parseError = nil
        }
        .onChange(of: category) {
            if !filtered.contains(where: { $0.id == selectedID }) { selectedID = filtered.first?.id }
        }
        .onChange(of: search) {
            if !filtered.contains(where: { $0.id == selectedID }) { selectedID = filtered.first?.id }
        }
        .confirmationDialog(
            selected?.isDestructive == true ? "Run destructive command?" : "Run command that changes state?",
            isPresented: $pendingConfirmedRun,
            titleVisibility: .visible
        ) {
            Button("Run Command", role: selected?.isDestructive == true ? .destructive : nil) { runSelected() }
            Button("Cancel", role: .cancel) { }
        } message: {
            Text(selected?.displayCommand(extraArguments: parsedExtraArguments ?? []) ?? "")
        }
    }

    @ViewBuilder
    private func commandDetail(_ command: CommandDefinition) -> some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(alignment: .firstTextBaseline) {
                VStack(alignment: .leading, spacing: 4) {
                    Text(command.title).font(.title2.weight(.semibold))
                    Text(command.summary).font(.callout).foregroundStyle(.secondary)
                }
                Spacer()
                Text(command.category.uppercased())
                    .font(.caption2.weight(.bold))
                    .padding(.horizontal, 7).padding(.vertical, 3)
                    .background(.quaternary, in: Capsule())
            }

            if command.requiresInput {
                VStack(alignment: .leading, spacing: 5) {
                    Text("Arguments").font(.caption.weight(.semibold))
                    TextField(command.usage.isEmpty ? "Additional arguments" : command.usage,
                              text: $extraArguments)
                        .textFieldStyle(.roundedBorder)
                        .font(.body.monospaced())
                    Text(command.usage).font(.caption2).foregroundStyle(.secondary)
                    if let parseError {
                        Label(parseError, systemImage: "exclamationmark.triangle")
                            .font(.caption).foregroundStyle(Cisco.red)
                    }
                }
            }

            VStack(alignment: .leading, spacing: 5) {
                Text("Command").font(.caption.weight(.semibold))
                Text(command.displayCommand(extraArguments: parsedExtraArguments ?? []))
                    .font(.system(.caption, design: .monospaced))
                    .textSelection(.enabled)
                    .padding(10)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(Cisco.surfacePanel, in: RoundedRectangle(cornerRadius: 8))
            }

            if command.requiresTerminal {
                Label("This command requires an interactive terminal session. Copy it and run it in Terminal.",
                      systemImage: "terminal")
                    .font(.caption).foregroundStyle(.secondary)
            }

            if running || exitCode != nil || !output.isEmpty {
                HStack {
                    if running { ProgressView().controlSize(.small) }
                    if let exitCode {
                        Image(systemName: exitCode == 0 ? "checkmark.circle.fill" : "xmark.circle.fill")
                            .foregroundStyle(exitCode == 0 ? Cisco.green : Cisco.red)
                        Text(exitCode == 0 ? "Completed" : "Failed (exit \(exitCode))")
                            .font(.subheadline.weight(.semibold))
                    } else {
                        Text("Running…").font(.subheadline)
                    }
                }
                ScrollView {
                    Text(output.isEmpty ? "Waiting for output…" : output)
                        .font(.system(.caption, design: .monospaced))
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                .padding(8)
                .background(Cisco.surfacePanel, in: RoundedRectangle(cornerRadius: 8))
            }

            Spacer()
            HStack {
                Button {
                    copyToPasteboard(command.displayCommand(extraArguments: parsedExtraArguments ?? []))
                } label: {
                    Label("Copy Command", systemImage: "doc.on.doc")
                }
                Spacer()
                if !command.requiresTerminal {
                    Button {
                        requestRun(command)
                    } label: {
                        Label(command.isDestructive ? "Review and Run" : "Run", systemImage: "play.fill")
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(command.isDestructive ? Cisco.red : Cisco.blue)
                    .keyboardShortcut(.defaultAction)
                    .disabled(running || (command.requiresInput && extraArguments.trimmingCharacters(in: .whitespaces).isEmpty))
                }
            }
        }
        .padding(18)
    }

    private var parsedExtraArguments: [String]? {
        do {
            return try CommandArgumentParser.parse(extraArguments)
        } catch {
            return nil
        }
    }

    private func requestRun(_ command: CommandDefinition) {
        do {
            _ = try CommandArgumentParser.parse(extraArguments)
            parseError = nil
        } catch {
            parseError = error.localizedDescription
            return
        }
        if command.isDestructive || command.changesState { pendingConfirmedRun = true }
        else { runSelected() }
    }

    private func runSelected() {
        guard let command = selected else { return }
        let extras: [String]
        do {
            extras = try CommandArgumentParser.parse(extraArguments)
            parseError = nil
        } catch {
            parseError = error.localizedDescription
            return
        }

        running = true
        output = ""
        exitCode = nil
        Task {
            let result = await appState.runCommand(
                title: command.title,
                binary: command.binary,
                arguments: command.arguments + extras,
                category: command.category,
                origin: "Command Palette",
                refreshOnSuccess: command.changesState
            )
            if let entry = appState.activity.entries.first(where: { $0.id == appState.activity.selectedID }) {
                output = entry.output
            }
            if output.isEmpty { output = result.output }
            exitCode = result.exitCode
            running = false
        }
    }
}

private enum CommandArgumentParser {
    struct ParseError: LocalizedError {
        let message: String
        var errorDescription: String? { message }
    }

    static func parse(_ input: String) throws -> [String] {
        var result: [String] = []
        var current = ""
        var quote: Character?
        var escaped = false

        for character in input {
            if escaped {
                current.append(character)
                escaped = false
                continue
            }
            if character == "\\" && quote != "'" {
                escaped = true
                continue
            }
            if let activeQuote = quote {
                if character == activeQuote { quote = nil }
                else { current.append(character) }
                continue
            }
            if character == "'" || character == "\"" {
                quote = character
            } else if character.isWhitespace {
                if !current.isEmpty {
                    result.append(current)
                    current = ""
                }
            } else {
                current.append(character)
            }
        }

        if escaped { throw ParseError(message: "The final backslash does not escape a character.") }
        if quote != nil { throw ParseError(message: "A quoted argument is not closed.") }
        if !current.isEmpty { result.append(current) }
        return result
    }
}
