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

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

import SwiftUI

/// A macOS front end for the canonical v8 redaction CLI. The primary controls
/// cover status and broad profile application; the disclosure below exposes the
/// complete non-interactive policy surface.
struct RedactionPolicySheet: View {
    @Environment(AppState.self) private var appState
    @Environment(\.dismiss) private var dismiss
    @State private var armed = false
    @State private var running = false
    @State private var profile = "sensitive"
    @State private var restart = false
    @State private var statusOutput = ""
    @State private var showAdvanced = false

    private let profiles = ["none", "sensitive", "content", "strict"]
    private var dangerous: Bool { profile == "none" }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Redaction policy").font(.headline)
            Text("Current global default: \(appState.config.redactionDefaultProfile.isEmpty ? "unset" : appState.config.redactionDefaultProfile)")
                .font(.callout.monospaced())
            Text("Bucket, destination, and route overrides may be more specific. View status for the canonical effective policy.")
                .font(.caption)
                .foregroundStyle(.secondary)
            Picker("Apply profile everywhere", selection: $profile) {
                ForEach(profiles, id: \.self) { Text($0).tag($0) }
            }
            .pickerStyle(.segmented)
            if dangerous {
                VStack(alignment: .leading, spacing: 3) {
                    Text("Profile none permits raw governed content in generated local SQLite and every configurable destination.")
                    Text("The release-owned managed enterprise destination remains locked.")
                }
                .font(.caption)
                .foregroundStyle(.secondary)
                Text("Only proceed if every downstream sink lives in the same trust boundary as this install.")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(Cisco.orange)
            } else {
                Text("This replaces every configurable profile override with \(profile); collection and routing stay unchanged.")
                .font(.caption)
                .foregroundStyle(.secondary)
            }
            Toggle("Restart gateway after applying", isOn: $restart)
            Text("The CLI previews, validates, backs up, writes atomically, and verifies the effective plan.")
                .font(.caption2)
                .foregroundStyle(.tertiary)
            DisclosureGroup("Show advanced settings", isExpanded: $showAdvanced) {
                RedactionAdvancedEditor(
                    running: $running,
                    output: $statusOutput
                )
                .padding(.top, 8)
            }
            if !statusOutput.isEmpty {
                ScrollView {
                    Text(statusOutput)
                        .font(.caption.monospaced())
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                .frame(maxHeight: 180)
            }
            if armed {
                Text("⚠ danger — click Apply again to proceed")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(Cisco.red)
            }
            HStack {
                Button("View status") { inspectStatus() }
                    .disabled(running)
                Spacer()
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button(running ? "Running…" : "Apply") { confirm() }
                    .buttonStyle(.borderedProminent)
                    .tint(dangerous ? Cisco.red : Cisco.green)
                    .disabled(running || !appState.installationMutationsAllowed)
            }
        }
        .padding(16)
        .frame(width: 560)
        .onAppear {
            if profiles.contains(appState.config.redactionDefaultProfile) {
                profile = appState.config.redactionDefaultProfile
            }
        }
        .onChange(of: profile) { _, _ in armed = false }
    }

    private func inspectStatus() {
        running = true
        Task {
            let result = await appState.runCommand(
                title: "setup redaction status",
                arguments: ["setup", "redaction", "status"],
                mutation: false,
                category: "setup",
                origin: "Logs"
            )
            statusOutput = result.output
            running = false
        }
    }

    private func confirm() {
        // Two-step confirmation for the unredacted profile.
        if dangerous, !armed {
            armed = true
            return
        }
        running = true
        Task {
            var arguments = [
                "setup", "redaction", "apply",
                "--scope", "all-configurable",
                "--profile", profile,
                "--yes",
            ]
            arguments.append(restart ? "--restart" : "--no-restart")
            let result = await appState.runCommand(
                title: "apply redaction profile \(profile)",
                arguments: arguments,
                category: "setup",
                origin: "Logs",
                successEffects: ["Redaction profile \(profile) applied to configurable projections"],
                refreshOnSuccess: true
            )
            running = false
            if result.succeeded {
                dismiss()
            } else {
                armed = false
                statusOutput = result.output.isEmpty
                    ? "Command failed with exit \(result.exitCode)."
                    : result.output
            }
        }
    }
}

/// Complete non-interactive redaction surface for the macOS app. The view
/// builds the same argv accepted by the CLI and defaults every mutation to a
/// canonical dry-run, so platform UI and automation share one policy engine.
private struct RedactionAdvancedEditor: View {
    @Environment(AppState.self) private var appState
    @Binding var running: Bool
    @Binding var output: String

    @State private var action: RedactionAdvancedAction = .status
    @State private var selectedBucket = "compliance.activity"
    @State private var policyProfile = "sensitive"
    @State private var logs = "unchanged"
    @State private var traces = "unchanged"
    @State private var metrics = "unchanged"
    @State private var customProfile = ""
    @State private var extendsProfile = "sensitive"
    @State private var detectors = ""
    @State private var metadataMode = "unchanged"
    @State private var identifierMode = "unchanged"
    @State private var contentMode = "unchanged"
    @State private var reasonMode = "unchanged"
    @State private var evidenceMode = "unchanged"
    @State private var errorMode = "unchanged"
    @State private var pathMode = "unchanged"
    @State private var credentialMode = "unchanged"
    @State private var replacementProfile = ""
    @State private var destination = ""
    @State private var routeName = ""
    @State private var signals = "logs,traces"
    @State private var routeBuckets = ""
    @State private var sources = ""
    @State private var connectors = ""
    @State private var producerActions = ""
    @State private var eventNames = ""
    @State private var minimumSeverity = "none"
    @State private var routeAction = "send"
    @State private var position = ""
    @State private var dryRun = true
    @State private var emitJSON = false
    @State private var restart = false

    private let buckets = [
        "compliance.activity", "security.finding", "guardrail.evaluation",
        "enforcement.action", "model.io", "tool.activity", "asset.scan",
        "asset.lifecycle", "network.egress", "agent.lifecycle", "ai.discovery",
        "telemetry.ingest", "platform.health", "diagnostic",
    ]
    private let triStates = ["unchanged", "on", "off"]
    private let fieldModes = ["unchanged", "inherit", "preserve", "detect", "whole", "hash", "remove"]

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Picker("Action", selection: $action) {
                ForEach(RedactionAdvancedAction.allCases) { item in
                    Text(item.rawValue).tag(item)
                }
            }
            .pickerStyle(.menu)

            ScrollView {
                VStack(alignment: .leading, spacing: 9) {
                    actionFields
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            .frame(maxHeight: 330)

            if let validationError {
                Text(validationError)
                    .font(.caption)
                    .foregroundStyle(Cisco.orange)
            }

            HStack(spacing: 14) {
                if action.supportsJSON {
                    Toggle("JSON", isOn: $emitJSON)
                }
                if action.isMutation {
                    Toggle("Dry run", isOn: $dryRun)
                    Toggle("Restart", isOn: $restart)
                        .disabled(dryRun)
                }
                Spacer()
                Button(buttonLabel) { runAction() }
                    .buttonStyle(.borderedProminent)
                    .disabled(
                        running || validationError != nil ||
                        (action.isMutation && !dryRun && !appState.installationMutationsAllowed)
                    )
            }
            Text(commandPreview)
                .font(.caption2.monospaced())
                .foregroundStyle(.secondary)
                .textSelection(.enabled)
                .lineLimit(3)
        }
        .padding(10)
        .background(.quaternary.opacity(0.35), in: RoundedRectangle(cornerRadius: 8))
        .onChange(of: action) { _, _ in
            resetActionFields()
        }
    }

    private func resetActionFields() {
        // Re-arm safe defaults and clear every action-scoped value so a prior
        // mutation cannot silently carry into a newly selected operation.
        selectedBucket = buckets[0]
        policyProfile = "sensitive"
        logs = "unchanged"
        traces = "unchanged"
        metrics = "unchanged"
        customProfile = ""
        extendsProfile = "sensitive"
        detectors = ""
        metadataMode = "unchanged"
        identifierMode = "unchanged"
        contentMode = "unchanged"
        reasonMode = "unchanged"
        evidenceMode = "unchanged"
        errorMode = "unchanged"
        pathMode = "unchanged"
        credentialMode = "unchanged"
        replacementProfile = ""
        destination = ""
        routeName = ""
        signals = "logs,traces"
        routeBuckets = action == .destinationSend ? "*" : ""
        sources = ""
        connectors = ""
        producerActions = ""
        eventNames = ""
        minimumSeverity = "none"
        routeAction = "send"
        position = ""
        dryRun = true
        emitJSON = false
        restart = false
        output = ""
    }

    @ViewBuilder
    private var actionFields: some View {
        switch action {
        case .status, .removeAll, .defaultsReset, .bucketList, .profileList:
            Text(action.rawValue + " requires no additional settings.")
                .font(.caption)
                .foregroundStyle(.secondary)

        case .applyAll, .applyDefaults:
            labeledTextField("Profile", text: $policyProfile, prompt: "built-in or custom profile")

        case .defaultsSet:
            labeledTextField("Profile (blank keeps current)", text: $policyProfile, prompt: "sensitive")
            collectionPickers

        case .bucketSet:
            bucketPicker
            labeledTextField("Profile (blank keeps current; inherit removes override)", text: $policyProfile)
            collectionPickers

        case .bucketReset:
            bucketPicker

        case .profileShow:
            labeledTextField("Profile", text: $customProfile)

        case .profileSet:
            labeledTextField("Custom profile name", text: $customProfile)
            Picker("Extends", selection: $extendsProfile) {
                ForEach(["sensitive", "content", "strict"], id: \.self) { Text($0).tag($0) }
            }
            .pickerStyle(.segmented)
            labeledTextField("Detector groups (comma-separated; blank keeps current)", text: $detectors,
                             prompt: "pii,credentials,secrets")
            Text("Field-class modes")
                .font(.caption.weight(.semibold))
            LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], spacing: 8) {
                fieldModePicker("metadata", selection: $metadataMode)
                fieldModePicker("identifier", selection: $identifierMode)
                fieldModePicker("content", selection: $contentMode)
                fieldModePicker("reason", selection: $reasonMode)
                fieldModePicker("evidence", selection: $evidenceMode)
                fieldModePicker("error", selection: $errorMode)
                fieldModePicker("path", selection: $pathMode)
                fieldModePicker("credential", selection: $credentialMode)
            }

        case .profileRemove:
            labeledTextField("Custom profile name", text: $customProfile)
            labeledTextField("Replace references with (blank requires unreferenced)", text: $replacementProfile)

        case .destinationShow, .destinationInherit:
            labeledTextField("Destination name", text: $destination)

        case .destinationSend:
            labeledTextField("Destination name", text: $destination)
            labeledTextField("Signals (comma-separated)", text: $signals, prompt: "logs,traces")
            labeledTextField("Buckets (comma-separated or *)", text: $routeBuckets, prompt: "*")
            labeledTextField("Profile (blank inherits)", text: $policyProfile)

        case .routeList:
            labeledTextField("Destination name", text: $destination)

        case .routeAdd, .routeSet:
            labeledTextField("Destination name", text: $destination)
            labeledTextField("Route name", text: $routeName)
            if action == .routeAdd {
                labeledTextField("One-based position (blank appends)", text: $position)
            }
            labeledTextField("Signals (comma-separated)", text: $signals, prompt: "logs,traces")
            labeledTextField("Bucket selectors (blank means any)", text: $routeBuckets)
            labeledTextField("Source selectors", text: $sources)
            labeledTextField("Connector selectors", text: $connectors)
            labeledTextField("Producer-action selectors", text: $producerActions)
            labeledTextField("Event-name selectors", text: $eventNames)
            HStack {
                Picker("Minimum severity", selection: $minimumSeverity) {
                    ForEach(["none", "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"], id: \.self) {
                        Text($0).tag($0)
                    }
                }
                Picker("Route action", selection: $routeAction) {
                    Text("send").tag("send")
                    Text("drop").tag("drop")
                }
            }
            if routeAction == "send" {
                labeledTextField("Profile (blank inherits)", text: $policyProfile)
            }

        case .routeMove:
            labeledTextField("Destination name", text: $destination)
            labeledTextField("Route name", text: $routeName)
            labeledTextField("One-based position", text: $position)

        case .routeRemove:
            labeledTextField("Destination name", text: $destination)
            labeledTextField("Route name", text: $routeName)
        }
    }

    private var bucketPicker: some View {
        Picker("Bucket", selection: $selectedBucket) {
            ForEach(buckets, id: \.self) { Text($0).tag($0) }
        }
        .pickerStyle(.menu)
    }

    private var collectionPickers: some View {
        HStack {
            triStatePicker("Logs", selection: $logs)
            triStatePicker("Traces", selection: $traces)
            triStatePicker("Metrics", selection: $metrics)
        }
    }

    private func labeledTextField(
        _ label: String,
        text: Binding<String>,
        prompt: String = ""
    ) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(label).font(.caption)
            TextField(prompt, text: text)
                .textFieldStyle(.roundedBorder)
        }
    }

    private func triStatePicker(_ label: String, selection: Binding<String>) -> some View {
        Picker(label, selection: selection) {
            ForEach(triStates, id: \.self) { Text($0).tag($0) }
        }
        .pickerStyle(.menu)
    }

    private func fieldModePicker(_ label: String, selection: Binding<String>) -> some View {
        Picker(label, selection: selection) {
            ForEach(fieldModes, id: \.self) { Text($0).tag($0) }
        }
        .pickerStyle(.menu)
    }

    private var options: RedactionCommandOptions {
        RedactionCommandOptions(
            action: action,
            selectedBucket: selectedBucket,
            policyProfile: policyProfile,
            logs: logs,
            traces: traces,
            metrics: metrics,
            customProfile: customProfile,
            extendsProfile: extendsProfile,
            detectors: detectors,
            metadataMode: metadataMode,
            identifierMode: identifierMode,
            contentMode: contentMode,
            reasonMode: reasonMode,
            evidenceMode: evidenceMode,
            errorMode: errorMode,
            pathMode: pathMode,
            credentialMode: credentialMode,
            replacementProfile: replacementProfile,
            destination: destination,
            routeName: routeName,
            signals: signals,
            routeBuckets: routeBuckets,
            sources: sources,
            connectors: connectors,
            producerActions: producerActions,
            eventNames: eventNames,
            minimumSeverity: minimumSeverity,
            routeAction: routeAction,
            position: position,
            dryRun: dryRun,
            emitJSON: emitJSON,
            restart: restart
        )
    }

    private var validationError: String? { options.validationError }

    private var buttonLabel: String {
        if running { return "Running…" }
        if !action.isMutation { return "Run" }
        return dryRun ? "Preview" : "Apply"
    }

    private var commandPreview: String {
        (["defenseclaw"] + buildArguments()).map(ShellQuoting.quote).joined(separator: " ")
    }

    private func buildArguments() -> [String] { options.buildArguments() }

    private func runAction() {
        guard validationError == nil else { return }
        let arguments = buildArguments()
        running = true
        Task {
            let result = await appState.runCommand(
                title: action.rawValue,
                arguments: arguments,
                mutation: action.isMutation && !dryRun,
                category: "setup",
                origin: "Logs / Redaction advanced",
                successEffects: action.isMutation && !dryRun ? ["Redaction policy updated and verified"] : [],
                refreshOnSuccess: action.isMutation && !dryRun
            )
            let resultOutput = result.output.isEmpty
                ? (result.succeeded
                    ? "\(action.rawValue) completed with no output."
                    : "Command failed with exit \(result.exitCode).")
                : result.output
            if result.succeeded, action.isMutation, !dryRun {
                resetActionFields()
            }
            output = resultOutput
            running = false
        }
    }
}
