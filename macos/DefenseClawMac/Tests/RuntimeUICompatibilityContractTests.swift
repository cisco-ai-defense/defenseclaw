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

@main
enum RuntimeUICompatibilityContractTests {
    static func main() throws {
        guard CommandLine.arguments.count == 2 else {
            fputs("Usage: RuntimeUICompatibilityContractTests <repository-root>\n", stderr)
            exit(2)
        }

        let root = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
        let configEditorSource = try source(
            at: root.appendingPathComponent("DefenseClawMac/Features/ConfigEditorDefinitions.swift")
        )
        let modelsSource = try source(
            at: root.appendingPathComponent("DefenseClawMac/DataLayer/Models.swift")
        )
        let logsSource = try source(
            at: root.appendingPathComponent("DefenseClawMac/Features/LogsView.swift")
        )

        expect(!configEditorSource.contains("privacy.disable_redaction"),
               "the config editor must not expose the removed privacy.disable_redaction key")
        expect(!configEditorSource.contains("ai_discovery.lookup_model_provenance_online"),
               "the offline editor must not expose the mainline-only online provenance option to runtime 0.8.10")
        expect(modelsSource.contains(#"case "amp": return "Amp""#),
               "the runtime-supported Amp connector must retain its display name")

        for unsupportedSurface in [
            "setup redaction",
            "RedactionToggleSheet",
            "showRedactionToggle",
            "redactionButton",
        ] {
            expect(!logsSource.contains(unsupportedSurface),
                   "the Logs UI must not expose the unsupported runtime 0.8.10 surface: \(unsupportedSurface)")
        }

        expect(logsSource.contains(".dcInspector(isPresented:"),
               "the Logs view must use the shared inline detail pane")
        expect(!logsSource.contains(".inspector(isPresented:"),
               "the Logs view must not restore the nested native inspector crash path")

        print("RuntimeUICompatibilityContractTests passed")
    }

    private static func source(at url: URL) throws -> String {
        try String(contentsOf: url, encoding: .utf8)
    }

    private static func expect(_ condition: @autoclosure () -> Bool, _ message: String) {
        guard condition() else {
            fputs("FAILED: \(message)\n", stderr)
            exit(1)
        }
    }
}
