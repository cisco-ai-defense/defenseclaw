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

// The Claude Cowork row of `defenseclaw status --json` (the `cowork` object,
// cli/defenseclaw/cowork.py CoworkStatus.as_dict). The key is absent when
// Cowork plays no part on this account and on runtimes older than 1.0.8, so
// a missing key reads as "no Cowork row", never as "not protected".

import Foundation

struct CoworkStatus: Sendable, Equatable {
    var protected: Bool
    var detail: String
    var step: String
    var reasonCode: String
    var lastEventAt: String
    var pluginVersion: String
    var pluginZip: String

    /// Parse the `cowork` object out of `status --json` output. Diagnostic
    /// text around the JSON is tolerated, as for the other CLI reports.
    static func parse(_ output: String) -> CoworkStatus? {
        guard let start = output.firstIndex(of: "{"),
              let end = output.lastIndex(of: "}"),
              start <= end,
              let root = try? JSONSerialization.jsonObject(
                  with: Data(output[start...end].utf8)
              ) as? [String: Any],
              let cowork = root["cowork"] as? [String: Any],
              let protected = cowork["protected"] as? Bool
        else { return nil }
        func text(_ key: String) -> String {
            (cowork[key] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        }
        return CoworkStatus(
            protected: protected,
            detail: text("detail"),
            step: text("step"),
            reasonCode: text("reason_code"),
            lastEventAt: text("last_event_at"),
            pluginVersion: text("plugin_version"),
            pluginZip: text("plugin_zip")
        )
    }

    /// The Overview rows, as the TUI's `cowork_overview_rows`: "Cowork" says
    /// protected or not and when the last Cowork event arrived (a clock time,
    /// so the box only changes when the content does); "Cowork next" names the
    /// missing step while Cowork is not protected. `home` is shortened to "~".
    func overviewRows(
        home: String = "", now: Date = Date(), calendar: Calendar = .current
    ) -> [(label: String, value: String)] {
        var state = detail
        if let cut = state.firstIndex(where: { ":,(".contains($0) }) {
            state = String(state[..<cut])
        }
        state = state.trimmingCharacters(in: .whitespaces)
        if state.isEmpty { state = protected ? "protected" : "not protected" }
        let clock = Self.clockText(lastEventAt, now: now, calendar: calendar)
        let value = clock.isEmpty ? "\(state), no Cowork event yet" : "\(state), last event \(clock)"
        var rows = [(label: "Cowork", value: value)]
        if !step.isEmpty, !protected {
            var shown = step
            var base = home
            while base.hasSuffix("/") || base.hasSuffix("\\") { base.removeLast() }
            if !base.isEmpty, home != "/", home != "~" {
                shown = shown.replacingOccurrences(of: base, with: "~")
            }
            rows.append((label: "Cowork next", value: shown))
        }
        return rows
    }

    /// "14:02:11" for today, "Oct 02 14:02" earlier, "" when unparseable.
    static func clockText(_ raw: String, now: Date = Date(), calendar: Calendar = .current) -> String {
        let trimmed = raw.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty else { return "" }
        let fractional = ISO8601DateFormatter()
        fractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        let plain = ISO8601DateFormatter()
        plain.formatOptions = [.withInternetDateTime]
        guard let stamp = fractional.date(from: trimmed) ?? plain.date(from: trimmed) else { return "" }
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.calendar = calendar
        formatter.timeZone = calendar.timeZone
        formatter.dateFormat = calendar.isDate(stamp, inSameDayAs: now) ? "HH:mm:ss" : "MMM dd HH:mm"
        return formatter.string(from: stamp)
    }
}
