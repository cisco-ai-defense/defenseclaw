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

// Config editor contracts against runtime 1.0.3: config_writer.restart_required
// (config_diff.py save_label), tui/panels/setup.py _rebase_config_draft, and
// tui/app.py _config_error_summary.

import Foundation

@main
struct ConfigEditorContractTests {
    static func main() {
        restartIsQueuedOnlyForKeysTheGatewayReadsAtStart()
        anOpenDraftSurvivesADiskGeneration()
        invalidConfigIsNamedWithItsLine()
        print("Config editor contract tests passed")
    }

    private static func restartIsQueuedOnlyForKeysTheGatewayReadsAtStart() {
        let required = ConfigRestartPolicy.restartRequired([
            "gateway.api_port", "gateway", "gateway.watcher.interval", "gateway.config_reload.mode",
            "gateway.config_reload.debounce_ms", "guardrail.mode", "guardrail.port", "scanners.skill_scanner.policy",
            "fleet.enabled", "fleet", "observability.local.path", "observability.destinations[0].enabled",
        ])
        expect(required == ["gateway.api_port", "gateway", "gateway.config_reload.mode", "guardrail.port", "fleet.enabled", "fleet", "observability.local.path"],
               "only the keys the gateway reads once at start need a restart: \(required)")
        expect(ConfigRestartPolicy.restartRequired(["guardrail.mode", "admission.skill.default"]).isEmpty, "hot-reloaded keys save without a restart")
    }

    private static func anOpenDraftSurvivesADiskGeneration() {
        let original = ["guardrail.mode": "observe", "gateway.api_port": "18970", "llm.model": "a"]
        let edited = ["guardrail.mode": "action", "gateway.api_port": "18971", "llm.model": "a"]
        // Another writer moved gateway.api_port and llm.model on disk.
        let fresh = ["guardrail.mode": "observe", "gateway.api_port": "19000", "llm.model": "b"]
        let rebased = ConfigDraftRebase.rebase(original: original, edited: edited, diskChanged: [], fresh: fresh)
        expect(rebased.edited == ["guardrail.mode": "action", "gateway.api_port": "18971"], "edits still differing from disk are kept; an untouched key is dropped: \(rebased.edited)")
        expect(rebased.diskChanged == ["gateway.api_port"], "only an edited key another writer changed is marked: \(rebased.diskChanged)")
        // The writer later lands the same value the draft holds: no change left.
        let settled = ConfigDraftRebase.rebase(original: fresh, edited: rebased.edited, diskChanged: rebased.diskChanged,
                                               fresh: ["guardrail.mode": "action", "gateway.api_port": "18971", "llm.model": "b"])
        expect(settled.edited.isEmpty && settled.diskChanged.isEmpty, "a draft equal to disk is no draft: \(settled)")
        let saved = ConfigDraftRebase.rebase(original: [:], edited: [:], diskChanged: [], fresh: fresh)
        expect(saved.edited.isEmpty, "a fresh load has no draft")
    }

    private static func invalidConfigIsNamedWithItsLine() {
        let output = """
          Config: /Users/x/.defenseclaw/config.yaml
          ✓ file exists
          ✗ parse error: invalid YAML at line 12, column 3 (mapping values are not allowed here). Fix that line, then check it with 'defenseclaw config validate'
        """
        expect(ConfigValidation.invalidConfigSummary(fileName: "config.yaml", exitCode: 1, output: output)
               == "config.yaml line 12 is invalid; run defenseclaw config validate", "the banner names the line")
        // What 1.0.3's `config validate` actually prints for a malformed file.
        let v103 = """
          Config: /Users/x/.defenseclaw/config.yaml
          OK file exists
          X line 4, column 10: invalid YAML (expected ',' or ']', but got ':'). Fix that line in config.yaml, then run 'defenseclaw config validate' again
        """
        expect(ConfigValidation.invalidConfigSummary(fileName: "config.yaml", exitCode: 1, output: v103)
               == "config.yaml line 4 is invalid; run defenseclaw config validate", "the 1.0.3 wording is recognised")
        expect(ConfigValidation.invalidConfigSummary(fileName: "config.yaml", exitCode: 1,
               output: "  X line 3: guardrail.mode is \"bogus\"; allowed values: observe, action.") == nil,
               "a semantic issue on a file that loads is not a load failure")
        expect(ConfigValidation.invalidConfigSummary(fileName: "config.yaml", exitCode: 1, output: "  X line 2: deployment_mode is \"bogus\"; allowed values: managed_enterprise, unmanaged_byod")
               == "config.yaml line 2 is invalid; run defenseclaw config validate", "a deployment_mode the loader refuses is a load failure")
        expect(ConfigValidation.invalidConfigSummary(fileName: "config.yaml", exitCode: 0, output: "config is valid") == nil, "a valid file raises nothing")
        expect(ConfigValidation.invalidConfigSummary(fileName: "config.yaml", exitCode: 1, output: "✗ guardrail.mode: unknown value") == nil,
               "a semantic issue the file still loads with is not a load failure")
        expect(ConfigValidation.invalidConfigSummary(fileName: "config.yaml", exitCode: 2, output: "Usage: defenseclaw config [OPTIONS]") == nil,
               "an older runtime without the command raises nothing")
        expect(ConfigValidation.invalidConfigSummary(fileName: "config.yaml", exitCode: 127, output: "defenseclaw binary not found.") == nil, "no CLI, no verdict")
        expect(ConfigValidation.invalidConfigSummary(fileName: "config.yaml", exitCode: 1, output: "parse error: the file is not valid UTF-8 text")
               == "config.yaml is invalid; run defenseclaw config validate", "no line when the runtime names none")
    }

    private static func expect(_ condition: @autoclosure () -> Bool, _ label: String) {
        guard condition() else {
            fputs("FAILED: \(label)\n", stderr)
            exit(1)
        }
    }
}
