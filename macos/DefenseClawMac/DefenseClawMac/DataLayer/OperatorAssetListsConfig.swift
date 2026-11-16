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

// The config.yaml side of OperatorAssetLists: reading the lists and the
// enterprise profile out of the parsed file (YAMLNode). Kept apart from the
// pure merge/count logic so audit-store harnesses compile without the
// config parser.

import Foundation

extension OperatorAssetLists {
    /// Reads the lists from a parsed config.yaml. `environment` supplies the
    /// `DEFENSECLAW_ENTERPRISE_PROFILE` pin the runtime honours.
    static func read(
        raw: YAMLNode,
        environment: [String: String] = ProcessInfo.processInfo.environment
    ) -> OperatorAssetLists {
        var allowed: [String: [OperatorAssetRule]] = [:]
        var denied: [String: [OperatorAssetRule]] = [:]
        for type in assetTypes {
            allowed[type] = rules(raw["asset_policy.\(type).allowed"])
            denied[type] = rules(raw["asset_policy.\(type).denied"])
        }
        return OperatorAssetLists(
            secureClient: enterpriseProfile(raw: raw, environment: environment) == "secure_client",
            allowed: allowed,
            denied: denied
        )
    }

    /// cmd_status._enterprise_profile: "" unless the install is
    /// managed_enterprise; then the service pin, the config's
    /// `enterprise.profile`, or the per-OS default (secure_client on macOS). A
    /// pin that contradicts the declared profile is ignored.
    static func enterpriseProfile(raw: YAMLNode, environment: [String: String]) -> String {
        let mode = (raw["deployment_mode"]?.string ?? "").trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard mode == "managed_enterprise" || mode == "managed" else { return "" }
        let pinned = (environment["DEFENSECLAW_ENTERPRISE_PROFILE"] ?? "")
            .trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let configured = (raw["enterprise.profile"]?.string ?? "")
            .trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if !pinned.isEmpty, configured.isEmpty || pinned == configured { return pinned }
        if !configured.isEmpty { return configured }
        return "secure_client"
    }

    /// The rules of one list; entries without a name are ignored, as the
    /// runtime ignores them.
    static func rules(_ node: YAMLNode?) -> [OperatorAssetRule] {
        guard let items = node?.sequence else { return [] }
        return items.compactMap { item in
            guard let fields = item.mapping else { return nil }
            let name = (fields["name"]?.string ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
            guard !name.isEmpty else { return nil }
            return OperatorAssetRule(
                name: name,
                connector: (fields["connector"]?.string ?? "").trimmingCharacters(in: .whitespacesAndNewlines),
                reason: fields["reason"]?.string ?? ""
            )
        }
    }
}
