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

    static func initializationArguments(
        detectedConnectors: [String],
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
    ) -> [String] {
        var arguments = ["init", "--non-interactive", "--yes", "--json-summary"]
        if detectedConnectors.isEmpty {
            arguments += ["--connector", normalizedConnector(fallbackConnector)]
        } else {
            arguments.append("--observe-all")
            if profile == "action" {
                let selected = detectedConnectors
                    .map(normalizedConnector)
                    .filter { actionConnectors.contains($0) }
                if !selected.isEmpty {
                    arguments += ["--action-connectors", selected.joined(separator: ",")]
                }
            }
        }
        arguments += ["--profile", profile]
        arguments += [
            "--scanner-mode", scannerMode,
            llmJudge ? "--with-judge" : "--no-judge",
            "--fail-mode", failMode,
        ]
        if profile == "action" {
            arguments.append(humanApproval ? "--human-approval" : "--no-human-approval")
            if humanApproval { arguments += ["--hilt-min-severity", hiltSeverity] }
        }
        arguments.append(startGateway ? "--start-gateway" : "--no-start-gateway")
        arguments.append(verify ? "--verify" : "--no-verify")
        return arguments
    }

    static func normalizedConnector(_ connector: String) -> String {
        let normalized = connector.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return normalized == "claude-code" ? "claudecode" : normalized
    }
}
