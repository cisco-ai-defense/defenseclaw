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

// Runtime-generated config-editor catalog. The installed DefenseClaw runtime
// ships its own Setup section catalog (tui/panels/setup.py
// build_setup_sections) — dumping it through the venv python means the Mac
// editor gains new sections/fields the moment the runtime is upgraded, with
// no Mac code changes. The static ConfigEditorCatalog stays as the offline
// fallback, and a read-only "Other (uncatalogued)" section surfaces config
// keys that even the runtime catalog doesn't describe yet. The runtime writer
// cannot safely persist truly unmodelled keys, so this fallback never claims
// a successful edit that Config.save() would silently discard.

import Foundation

enum DynamicConfigCatalog {
    /// Sentinel-prefixed dump so CLIRunner's merged stdout/stderr (Python
    /// warnings etc.) can't corrupt the JSON parse.
    static let sentinel = "DCCATALOG:"

    static let dumpScript = """
    import json
    from defenseclaw import config as dc_config
    from defenseclaw.tui.panels.setup import build_setup_sections
    cfg = dc_config.load()
    out = []
    for s in build_setup_sections(cfg):
        fields = []
        for f in s.fields:
            kind = str(f.kind)
            # Passwords are write-only in the editor — never ship the value.
            value = "" if kind == "password" else str(f.value)
            fields.append({
                "label": f.label, "key": f.key, "kind": kind,
                "value": value, "options": [str(o) for o in f.options],
                "hint": f.hint,
            })
        out.append({"name": s.name, "summary": s.summary,
                    "help": getattr(s, "help", ""), "fields": fields})
    print(\(String(reflecting: sentinel)) + json.dumps(out))
    """

    /// One dumped field's resolved value, keyed by config path — seeds the
    /// editor's "original" values so no separate YAML read is needed.
    struct LoadResult {
        var sections: [ConfigEditorSection]
        var values: [String: String]
    }

    /// Dump the runtime's catalog. nil on any failure (missing venv, renamed
    /// symbol in a future runtime, parse error) — callers fall back to the
    /// static catalog.
    static func load(using cli: CLIRunner, context: InstallationContext) async -> LoadResult? {
        let runtimePython = context.runtimePythonURL.path
        guard FileManager.default.isExecutableFile(atPath: runtimePython) else { return nil }
        let result = await cli.run(binary: runtimePython, arguments: ["-c", dumpScript], mutation: false)
        guard result.succeeded,
              let line = result.output.split(separator: "\n").first(where: { $0.hasPrefix(sentinel) }),
              let data = String(line.dropFirst(sentinel.count)).data(using: .utf8),
              let raw = (try? JSONSerialization.jsonObject(with: data)) as? [[String: Any]]
        else { return nil }

        var values: [String: String] = [:]
        let sections: [ConfigEditorSection] = raw.compactMap { section in
            guard let name = section["name"] as? String else { return nil }
            let fields: [ConfigEditorField] = ((section["fields"] as? [Any]) ?? []).compactMap { item in
                guard let row = item as? [String: Any],
                      let label = row["label"] as? String else { return nil }
                let key = (row["key"] as? String) ?? ""
                let kind = Self.kind((row["kind"] as? String) ?? "string")
                let value = (row["value"] as? String) ?? ""
                if !key.isEmpty, kind != .header, kind != .password {
                    values[key] = value
                }
                return ConfigEditorField(
                    label: label,
                    key: key,
                    kind: kind,
                    options: (row["options"] as? [String]) ?? [],
                    hint: (row["hint"] as? String) ?? "",
                    headerValue: kind == .header ? value : ""
                )
            }
            return ConfigEditorSection(
                name: name,
                summary: (section["summary"] as? String) ?? "",
                help: (section["help"] as? String) ?? "",
                fields: fields
            )
        }
        guard !sections.isEmpty else { return nil }
        return LoadResult(sections: sections, values: values)
    }

    /// Unknown runtime kinds degrade to free-text so future field types stay
    /// editable rather than invisible.
    private static func kind(_ raw: String) -> ConfigEditorField.Kind {
        switch raw {
        case "bool": .bool
        case "int": .int
        case "choice": .choice
        case "password": .password
        case "header": .header
        default: .string
        }
    }

    /// Config keys not covered by the runtime catalog. These are deliberately
    /// read-only: `apply_config_field` cannot persist truly unmodelled fields,
    /// and it cannot infer the element type of an unknown sequence.
    static func uncataloguedSection(
        raw: YAMLNode,
        knownKeys: Set<String>
    ) -> (section: ConfigEditorSection, values: [String: String])? {
        var fields: [ConfigEditorField] = []
        let values: [String: String] = [:]

        func walk(_ node: YAMLNode, path: String) {
            switch node {
            case .scalar(let scalar):
                guard !path.isEmpty, !knownKeys.contains(path) else { return }
                let lower = path.lowercased()
                let secret = lower.contains("api_key")
                    || lower.contains("private_key")
                    || lower.contains("token")
                    || lower.contains("secret")
                    || lower.contains("password")
                    || lower.contains("credential")
                fields.append(ConfigEditorField(
                    label: path,
                    key: "",
                    kind: .header,
                    hint: "Uncatalogued key present in config.yaml (read only).",
                    headerValue: secret ? "configured (hidden)" : scalar
                ))
            case .mapping(let map):
                for key in map.keys.sorted() {
                    walk(map[key]!, path: path.isEmpty ? key : "\(path).\(key)")
                }
            case .sequence(let items):
                guard !path.isEmpty, !knownKeys.contains(path) else { return }
                fields.append(ConfigEditorField(
                    label: path,
                    key: "",
                    kind: .header,
                    hint: "Uncatalogued list present in config.yaml (read only).",
                    headerValue: "\(items.count) value\(items.count == 1 ? "" : "s")"
                ))
            }
        }
        walk(raw, path: "")
        guard !fields.isEmpty else { return nil }
        return (
            ConfigEditorSection(
                name: "Other (uncatalogued)",
                summary: "config.yaml keys the runtime catalog doesn't describe yet (read only).",
                help: "Upgrade the runtime to gain a typed editor for these fields, or edit config.yaml with the matching runtime documentation.",
                fields: fields
            ),
            values
        )
    }
}
