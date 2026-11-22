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

// Overview lines the TUI computes with runtime code rather than by reading
// config.yaml literally (runtime 1.0.7):
//
// * the SCANNERS "overrides" row — admission actions config.yaml sets that
//   differ from built-in policy, folded through enforce.admission_overrides
//   (per-type actions win over scanner-derived skill actions, which win over
//   admission.defaults.actions; only effective differences show);
// * the OBSERVABILITY storage policy — retention label, judge capture and
//   the two store paths from observability.v8_status.inspect_v8_operator_status
//   (the masked canonical effective plan, not the raw YAML).
//
// Both are dumped by the selected runtime's interpreter once per config
// generation; the live "controller=" half of the storage line comes from
// /health (HealthSnapshot.retentionState) and stays on the Mac side.

import Foundation

enum RuntimeOverviewSummary {
    /// Sentinel-prefixed dump so CLIRunner's merged stdout/stderr (Python
    /// warnings etc.) can't corrupt the JSON parse.
    static let sentinel = "DCOVERVIEW:"

    struct Storage: Equatable, Sendable {
        var retention: String
        var judgeCapture: String
        var localPath: String
        var judgeBodiesPath: String
    }

    struct Result: Equatable, Sendable {
        /// format_scanner_overrides_summary(admission_action_overrides(cfg)),
        /// "" for the common default config (nothing is shown).
        var admissionOverrides = ""
        /// nil for a non-v8 source or when the runtime could not answer.
        var storage: Storage?
        /// tui/app.py _fetch_v8_operator_status: only the validator-owned
        /// path and keyword cross over; arbitrary exception text never does.
        var storageError = ""
    }

    static let dumpScript = """
    import json, re
    out = {"admission_overrides": ""}
    try:
        from defenseclaw import config as dc_config
        from defenseclaw.enforce.admission_overrides import admission_action_overrides, format_scanner_overrides_summary
        out["admission_overrides"] = format_scanner_overrides_summary(admission_action_overrides(dc_config.load()))
    except Exception:
        pass
    try:
        from defenseclaw.config import config_path_for_data_dir
        from defenseclaw.observability.v8_status import inspect_v8_operator_status, source_is_v8
        path = config_path_for_data_dir(None)
        if source_is_v8(path):
            status = inspect_v8_operator_status(path)
            out["storage"] = {
                "retention": status.retention_label,
                "judge_capture": "enabled" if status.judge_bodies_enabled else "disabled",
                "local_path": status.local_path or "built-in data directory",
                "judge_bodies_path": status.judge_bodies_path or "built-in data directory",
            }
    except Exception as exc:
        path = getattr(exc, "path", "")
        keyword = getattr(exc, "keyword", "")
        if isinstance(path, str) and isinstance(keyword, str) and path and keyword:
            safe_path = re.sub(r"[^A-Za-z0-9_.$\\[\\]-]", "?", path)[:256]
            safe_keyword = re.sub(r"[^A-Za-z0-9_.-]", "?", keyword)[:64]
            out["storage_error"] = "invalid configuration at %s (%s)" % (safe_path, safe_keyword)
        else:
            out["storage_error"] = "telemetry status could not be loaded; run defenseclaw observability validate"
    print("DCOVERVIEW:" + json.dumps(out))
    """

    /// Parse the interpreter's merged output. nil when the sentinel line is
    /// missing or unreadable, so callers show nothing rather than a guess.
    static func parse(_ output: String) -> Result? {
        guard let line = output.split(separator: "\n").first(where: { $0.hasPrefix(sentinel) }),
              let data = String(line.dropFirst(sentinel.count)).data(using: .utf8),
              let raw = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
        else { return nil }
        var result = Result()
        result.admissionOverrides = bounded(raw["admission_overrides"])
        result.storageError = bounded(raw["storage_error"])
        if let storage = raw["storage"] as? [String: Any] {
            result.storage = Storage(
                retention: bounded(storage["retention"]),
                judgeCapture: bounded(storage["judge_capture"]) == "disabled" ? "disabled" : "enabled",
                localPath: bounded(storage["local_path"]),
                judgeBodiesPath: bounded(storage["judge_bodies_path"])
            )
        }
        return result
    }

    /// One display line per field: strings only, line breaks folded, bounded.
    private static func bounded(_ value: Any?) -> String {
        guard let text = value as? String else { return "" }
        let folded = text.split(whereSeparator: \.isNewline).joined(separator: " ")
        return String(folded.prefix(1024))
    }
}
