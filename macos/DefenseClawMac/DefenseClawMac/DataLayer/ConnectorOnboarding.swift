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

enum ConnectorOnboarding {
    static func installedConnectors(from discoveryOutput: String, supportedOrder: [String]) -> [String] {
        guard let start = discoveryOutput.firstIndex(of: "{"),
              let end = discoveryOutput.lastIndex(of: "}"),
              start <= end,
              let root = try? JSONSerialization.jsonObject(
                  with: Data(discoveryOutput[start...end].utf8)
              ) as? [String: Any],
              let agents = root["agents"] as? [String: Any]
        else { return [] }

        let installed = Set(agents.compactMap { key, value -> String? in
            guard let details = value as? [String: Any], details["installed"] as? Bool == true else {
                return nil
            }
            let candidate = (details["name"] as? String)?
                .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            let raw = candidate.isEmpty ? key : candidate
            return normalizedConnector(raw)
        })
        return supportedOrder.filter { installed.contains(normalizedConnector($0)) }
    }

    /// `defenseclaw setup` subcommand for a hook connector — only Claude Code
    /// is hyphenated in the CLI's command set.
    static func setupCommandName(_ connector: String) -> String {
        let normalized = normalizedConnector(connector)
        return normalized == "claudecode" ? "claude-code" : normalized
    }

    /// The command sequence for first-run initialization — one argv per
    /// element, executed in order. The first is always `init`; follow-ups are
    /// additive per-connector `setup` calls, needed only when the user
    /// registers a strict subset of the detected connectors (>1), which
    /// non-interactive init cannot express in a single invocation.
    static func initializationPlan(
        detectedConnectors: [String],
        registeredConnectors: Set<String>,
        fallbackConnector: String,
        actionConnectors: Set<String>,
        profile: String,
        scannerMode: String,
        llmJudge: Bool,
        failMode: String,
        humanApproval: Bool,
        hiltSeverity: String,
        startGateway: Bool,
        verify: Bool
    ) -> [[String]] {
        let detected = detectedConnectors.map(normalizedConnector)
        let registered = Set(registeredConnectors.map(normalizedConnector))
        var selected = detected.filter { registered.contains($0) }
        // The UI requires >=1 registered connector; if a caller ever passes an
        // empty selection anyway, register everything rather than
        // half-configure (mirrors the pre-checked default).
        if selected.isEmpty { selected = detected }
        let action = Set(actionConnectors.map(normalizedConnector)).intersection(selected)

        var head = ["init", "--non-interactive", "--yes", "--json-summary"]
        var followUps: [[String]] = []

        if detected.isEmpty {
            head += ["--connector", normalizedConnector(fallbackConnector), "--profile", profile]
        } else if selected.count == detected.count {
            head.append("--observe-all")
            if profile == "action" {
                let enforced = selected.filter(action.contains)
                if !enforced.isEmpty {
                    head += ["--action-connectors", enforced.joined(separator: ",")]
                }
            }
            // Keep the profile explicit for Cisco's non-interactive command
            // contract; the multi-connector flags still decide each peer's mode.
            head += ["--profile", profile]
        } else {
            // Strict subset: init configures one connector; the rest are added
            // with per-connector `setup`, which the runtime documents as
            // add-alongside-peers (never roster-replacing). Lead with an
            // action connector when enforcing so init carries the global
            // enforcement options (human approval etc.).
            let first = (profile == "action" ? selected.first(where: action.contains) : nil) ?? selected[0]
            let firstProfile = profile == "action" && action.contains(first) ? "action" : "observe"
            head += ["--connector", first, "--profile", firstProfile]
            let rest = selected.filter { $0 != first }
            for (index, name) in rest.enumerated() {
                var followUp = [
                    "setup", setupCommandName(name), "--yes",
                    "--mode", profile == "action" && action.contains(name) ? "action" : "observe",
                ]
                // Restart the gateway once, at the end, and only when the user
                // asked for it to run — intermediate restarts are churn, and a
                // gateway the user left stopped must stay stopped.
                if !startGateway || index < rest.count - 1 {
                    followUp.append("--no-restart")
                }
                followUps.append(followUp)
            }
        }

        head += [
            "--scanner-mode", scannerMode,
            llmJudge ? "--with-judge" : "--no-judge",
            "--fail-mode", failMode,
        ]
        if profile == "action" {
            head.append(humanApproval ? "--human-approval" : "--no-human-approval")
            if humanApproval { head += ["--hilt-min-severity", hiltSeverity] }
        }
        head.append(startGateway ? "--start-gateway" : "--no-start-gateway")
        head.append(verify ? "--verify" : "--no-verify")
        return [head] + followUps
    }

    static func normalizedConnector(_ connector: String) -> String {
        let normalized = connector.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return normalized == "claude-code" ? "claudecode" : normalized
    }
}
