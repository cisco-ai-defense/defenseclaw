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

struct PolicyCatalogSnapshot: Decodable, Sendable {
    var scopes: [String]
    var views: [PolicyCatalogView]

    func view(_ id: String, scope: String) -> PolicyCatalogView? {
        views.first { $0.id == id && ($0.scope.isEmpty || $0.scope == scope) }
    }

    static func decode(_ output: String) throws -> Self {
        guard let line = output.split(separator: "\n").first(where: { $0.hasPrefix("DCPOLICY:") }),
              let data = String(line.dropFirst("DCPOLICY:".count)).data(using: .utf8) else {
            throw CatalogCLIError.invalidJSON("Policy catalog marker missing")
        }
        let snapshot = try JSONDecoder().decode(Self.self, from: data)
        guard Set(snapshot.views.map(\.id)) == Set(PolicyCatalogView.identifiers),
              snapshot.views.allSatisfy({ view in
                  view.rows.allSatisfy { $0.cells.count == view.columns.count }
              }) else {
            throw CatalogCLIError.invalidJSON("Incomplete policy catalog")
        }
        return snapshot
    }
}

struct PolicyCatalogView: Decodable, Sendable {
    static let identifiers = ["posture", "optin", "chains", "families", "policies", "packs", "sandbox_packs"]
    static let titles = ["Posture", "Opt-in packs", "Chains", "Rule families", "Policies", "Rule packs", "Sandbox packs"]
    var id: String
    var scope: String
    var title: String
    var columns: [String]
    var rows: [PolicyCatalogRow]
    var empty: String
    var error: String
}

struct PolicyCatalogRow: Decodable, Sendable, Identifiable {
    var id: String
    var cells: [String]
    var detail: String
    var actions: [PolicyCatalogAction]

    func matches(_ query: String) -> Bool {
        query.isEmpty || (cells.joined(separator: " ") + " " + detail).localizedCaseInsensitiveContains(query)
    }
}

struct PolicyCatalogAction: Decodable, Sendable, Identifiable {
    var title: String
    var group: String
    var arguments: [String]
    var consequence: String
    var weaker: Bool
    var mutation: Bool
    var validationArguments: [String]?
    var id: String { arguments.joined(separator: "\u{1f}") }

    /// The catalog can only propose the policy commands this UI advertises.
    /// Execution always goes through the selected CLI, never a returned binary.
    var allowed: Bool {
        guard arguments.count >= 3, !arguments.contains(where: { $0.contains("\0") }) else { return false }
        if arguments.prefix(2) == ["guardrail", "use-pack"] {
            guard let validationArguments, validationArguments.count == 4,
                  validationArguments.prefix(2) == ["guardrail", "validate-pack"],
                  validationArguments.last == "--json" else { return false }
        }
        if !mutation { return arguments.prefix(2) == ["guardrail", "validate-pack"] && arguments.last == "--json" }
        if arguments[0] == "guardrail" {
            return ["mode", "block-at", "alert-at", "hilt", "use-pack", "protection"].contains(arguments[1])
        }
        return arguments.prefix(2) == ["policy", "activate"]
            || arguments.prefix(3) == ["policy", "edit", "guardrail"]
    }
}

enum PolicyCatalog {
    static func load(using cli: CLIRunner) async throws -> PolicyCatalogSnapshot {
        guard let python = await cli.locateRuntimePython(),
              let script = Bundle.main.url(forResource: "policy_catalog_bridge", withExtension: "py") else {
            throw CatalogCLIError.commandFailed("The policy catalog needs a compatible DefenseClaw runtime and the app's policy reader. Refresh after updating the runtime.")
        }
        let packs = await cli.run(arguments: ["sandbox", "pack", "list", "-o", "json"], mutation: false)
        let payload: [String: String] = packs.succeeded
            ? ["sandbox_json": packs.output]
            : ["sandbox_error": "Sandbox pack catalog unavailable: " + packs.output]
        let input = String(decoding: try JSONEncoder().encode(payload), as: UTF8.self)
        let result = await cli.run(binary: python, arguments: [script.path], standardInput: input, mutation: false)
        guard result.succeeded else {
            throw CatalogCLIError.commandFailed("Policy catalog could not be read. " + result.output)
        }
        return try PolicyCatalogSnapshot.decode(result.output)
    }
}
