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

import Foundation

enum RedactionAdvancedAction: String, CaseIterable, Identifiable {
    case status = "Inspect effective policy"
    case removeAll = "Remove all configurable redaction"
    case applyAll = "Apply profile everywhere"
    case applyDefaults = "Apply profile to defaults"
    case defaultsSet = "Set global defaults"
    case defaultsReset = "Reset global defaults"
    case bucketList = "List all buckets"
    case bucketSet = "Set bucket policy"
    case bucketReset = "Reset bucket policy"
    case profileList = "List profiles"
    case profileShow = "Show compiled profile"
    case profileSet = "Create or edit custom profile"
    case profileRemove = "Remove custom profile"
    case destinationShow = "Show destination policy"
    case destinationSend = "Set destination send policy"
    case destinationInherit = "Restore destination inheritance"
    case routeList = "List ordered routes"
    case routeAdd = "Add ordered route"
    case routeSet = "Replace ordered route"
    case routeMove = "Move ordered route"
    case routeRemove = "Remove ordered route"

    var id: String { rawValue }

    var isMutation: Bool {
        switch self {
        case .status, .bucketList, .profileList, .profileShow, .destinationShow, .routeList:
            false
        default:
            true
        }
    }

    var supportsJSON: Bool {
        switch self {
        case .status,
             .removeAll,
             .applyAll,
             .applyDefaults,
             .defaultsSet,
             .defaultsReset,
             .bucketSet,
             .bucketReset,
             .profileList,
             .profileShow,
             .profileSet,
             .profileRemove,
             .destinationSend,
             .destinationInherit,
             .routeList,
             .routeAdd,
             .routeSet,
             .routeMove,
             .routeRemove:
            true
        case .bucketList, .destinationShow:
            false
        }
    }
}

struct RedactionCommandOptions {
    var action: RedactionAdvancedAction = .status
    var selectedBucket = "compliance.activity"
    var policyProfile = "sensitive"
    var logs = "unchanged"
    var traces = "unchanged"
    var metrics = "unchanged"
    var customProfile = ""
    var extendsProfile = "sensitive"
    var detectors = ""
    var metadataMode = "unchanged"
    var identifierMode = "unchanged"
    var contentMode = "unchanged"
    var reasonMode = "unchanged"
    var evidenceMode = "unchanged"
    var errorMode = "unchanged"
    var pathMode = "unchanged"
    var credentialMode = "unchanged"
    var replacementProfile = ""
    var destination = ""
    var routeName = ""
    var signals = "logs,traces"
    var routeBuckets = ""
    var sources = ""
    var connectors = ""
    var producerActions = ""
    var eventNames = ""
    var minimumSeverity = "none"
    var routeAction = "send"
    var position = ""
    var dryRun = true
    var emitJSON = false
    var restart = false

    var validationError: String? {
        let hasCollectionChange = [logs, traces, metrics].contains { $0 != "unchanged" }
        switch action {
        case .applyAll, .applyDefaults:
            return trimmed(policyProfile).isEmpty ? "Enter a built-in or custom profile." : nil
        case .defaultsSet:
            return trimmed(policyProfile).isEmpty && !hasCollectionChange
                ? "Choose a profile or at least one collection change." : nil
        case .bucketSet:
            return trimmed(policyProfile).isEmpty && !hasCollectionChange
                ? "Choose a profile/inherit or at least one collection change." : nil
        case .profileShow, .profileSet, .profileRemove:
            return trimmed(customProfile).isEmpty ? "Enter a profile name." : nil
        case .destinationShow, .destinationInherit, .routeList:
            return trimmed(destination).isEmpty ? "Enter a destination name." : nil
        case .destinationSend:
            if trimmed(destination).isEmpty { return "Enter a destination name." }
            if csv(signals).isEmpty { return "Select at least one signal." }
            return csv(routeBuckets).isEmpty ? "Select at least one bucket or *." : nil
        case .routeAdd, .routeSet:
            if trimmed(destination).isEmpty { return "Enter a destination name." }
            if trimmed(routeName).isEmpty { return "Enter a route name." }
            if csv(signals).isEmpty { return "Select at least one signal." }
            if action == .routeAdd, !trimmed(position).isEmpty,
               (Int(trimmed(position)) ?? 0) < 1 {
                return "Position must be a positive integer."
            }
            return nil
        case .routeMove:
            if trimmed(destination).isEmpty { return "Enter a destination name." }
            if trimmed(routeName).isEmpty { return "Enter a route name." }
            return (Int(trimmed(position)) ?? 0) < 1 ? "Position must be a positive integer." : nil
        case .routeRemove:
            if trimmed(destination).isEmpty { return "Enter a destination name." }
            return trimmed(routeName).isEmpty ? "Enter a route name." : nil
        case .status, .removeAll, .defaultsReset, .bucketList, .bucketReset, .profileList:
            return nil
        }
    }

    func buildArguments() -> [String] {
        var arguments = ["setup", "redaction"]
        switch action {
        case .status:
            arguments.append("status")
        case .removeAll:
            arguments.append("remove-all")
        case .applyAll, .applyDefaults:
            arguments += ["apply", "--scope", action == .applyAll ? "all-configurable" : "defaults",
                          "--profile", trimmed(policyProfile)]
        case .defaultsSet:
            arguments += ["defaults", "set"]
            appendProfile(trimmed(policyProfile), inheritFlag: nil, to: &arguments)
            appendCollection(to: &arguments)
        case .defaultsReset:
            arguments += ["defaults", "reset"]
        case .bucketList:
            arguments += ["bucket", "list"]
        case .bucketSet:
            arguments += ["bucket", "set", selectedBucket]
            appendProfile(trimmed(policyProfile), inheritFlag: "--inherit-profile", to: &arguments)
            appendCollection(to: &arguments)
        case .bucketReset:
            arguments += ["bucket", "reset", selectedBucket]
        case .profileList:
            arguments += ["profile", "list"]
        case .profileShow:
            arguments += ["profile", "show", trimmed(customProfile)]
        case .profileSet:
            arguments += ["profile", "set", trimmed(customProfile), "--extends", extendsProfile]
            appendRepeated("--detector", values: csv(detectors), to: &arguments)
            for (name, mode) in fieldModeValues where mode != "unchanged" {
                arguments += ["--field", "\(name)=\(mode)"]
            }
        case .profileRemove:
            arguments += ["profile", "remove", trimmed(customProfile)]
            if !trimmed(replacementProfile).isEmpty {
                arguments += ["--replace-with", trimmed(replacementProfile)]
            }
        case .destinationShow:
            arguments += ["destination", "show", trimmed(destination)]
        case .destinationSend:
            arguments += ["destination", "send", trimmed(destination)]
            appendRepeated("--signal", values: csv(signals), to: &arguments)
            appendRepeated("--bucket", values: csv(routeBuckets), to: &arguments)
            if !trimmed(policyProfile).isEmpty {
                arguments += ["--profile", trimmed(policyProfile)]
            }
        case .destinationInherit:
            arguments += ["destination", "inherit", trimmed(destination)]
        case .routeList:
            arguments += ["route", "list", trimmed(destination)]
        case .routeAdd, .routeSet:
            arguments += ["route", action == .routeAdd ? "add" : "set", trimmed(destination), trimmed(routeName)]
            if action == .routeAdd, !trimmed(position).isEmpty {
                arguments += ["--position", trimmed(position)]
            }
            appendRouteOptions(to: &arguments)
        case .routeMove:
            arguments += ["route", "move", trimmed(destination), trimmed(routeName),
                          "--position", trimmed(position)]
        case .routeRemove:
            arguments += ["route", "remove", trimmed(destination), trimmed(routeName)]
        }
        if action.supportsJSON, emitJSON {
            arguments.append("--json")
        }
        if action.isMutation {
            arguments.append("--yes")
            if dryRun { arguments.append("--dry-run") }
            arguments.append(restart && !dryRun ? "--restart" : "--no-restart")
        }
        return arguments
    }

    private var fieldModeValues: [(String, String)] {
        [
            ("metadata", metadataMode), ("identifier", identifierMode),
            ("content", contentMode), ("reason", reasonMode),
            ("evidence", evidenceMode), ("error", errorMode),
            ("path", pathMode), ("credential", credentialMode),
        ]
    }

    private func appendProfile(_ value: String, inheritFlag: String?, to arguments: inout [String]) {
        guard !value.isEmpty else { return }
        if value == "inherit", let inheritFlag {
            arguments.append(inheritFlag)
        } else {
            arguments += ["--profile", value]
        }
    }

    private func appendCollection(to arguments: inout [String]) {
        for (signal, value) in [("logs", logs), ("traces", traces), ("metrics", metrics)] {
            if value == "on" { arguments.append("--\(signal)") }
            if value == "off" { arguments.append("--no-\(signal)") }
        }
    }

    private func appendRouteOptions(to arguments: inout [String]) {
        appendRepeated("--signal", values: csv(signals), to: &arguments)
        appendRepeated("--bucket", values: csv(routeBuckets), to: &arguments)
        appendRepeated("--source", values: csv(sources), to: &arguments)
        appendRepeated("--connector", values: csv(connectors), to: &arguments)
        appendRepeated("--producer-action", values: csv(producerActions), to: &arguments)
        appendRepeated("--event-name", values: csv(eventNames), to: &arguments)
        if minimumSeverity != "none" {
            arguments += ["--min-severity", minimumSeverity]
        }
        arguments += ["--route-action", routeAction]
        if routeAction == "send", !trimmed(policyProfile).isEmpty {
            arguments += ["--profile", trimmed(policyProfile)]
        }
    }

    private func appendRepeated(_ flag: String, values: [String], to arguments: inout [String]) {
        for value in values { arguments += [flag, value] }
    }

    private func csv(_ value: String) -> [String] {
        value.split(separator: ",").map { trimmed(String($0)) }.filter { !$0.isEmpty }
    }

    private func trimmed(_ value: String) -> String {
        value.trimmingCharacters(in: .whitespacesAndNewlines)
    }

}
