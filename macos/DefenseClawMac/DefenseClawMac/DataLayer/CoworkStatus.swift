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
    var lastEventAt: String

    /// What one `status --json` run says about Cowork. `status` exits 1 when
    /// it reports problems and still prints the report, so the caller reads
    /// the output, not the exit code: `.unreadable` (no JSON object, a
    /// failed run) keeps the last row; `.noCowork` clears it.
    enum Report: Equatable {
        case unreadable
        case noCowork
        case cowork(CoworkStatus)
    }

    /// Read the report out of `status --json` output. Diagnostic text around
    /// the JSON is tolerated, as for the other CLI reports.
    static func report(_ output: String) -> Report {
        guard let start = output.firstIndex(of: "{"),
              let end = output.lastIndex(of: "}"),
              start <= end,
              let root = try? JSONSerialization.jsonObject(
                  with: Data(output[start...end].utf8)
              ) as? [String: Any]
        else { return .unreadable }
        guard let cowork = root["cowork"] as? [String: Any],
              let protected = cowork["protected"] as? Bool
        else { return .noCowork }
        func text(_ key: String) -> String {
            (cowork[key] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        }
        return .cowork(CoworkStatus(
            protected: protected,
            detail: text("detail"),
            step: text("step"),
            lastEventAt: text("last_event_at")
        ))
    }

    /// The Cowork row of the output, or nil when it has none.
    static func parse(_ output: String) -> CoworkStatus? {
        if case .cowork(let status) = report(output) { return status }
        return nil
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

    // SwiftUI evaluates the Overview rows on every render, so the formatters
    // are built once. Parsing and formatting with them is thread-safe; they
    // are never changed after they are built.
    private static let fractionalStamp: ISO8601DateFormatter = {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter
    }()
    private static let plainStamp: ISO8601DateFormatter = {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]
        return formatter
    }()
    /// "HH:mm:ss" and "MMM dd HH:mm" in the user's current calendar and time
    /// zone (they follow a change of either).
    static let todayClock = makeClock("HH:mm:ss", calendar: .autoupdatingCurrent, timeZone: .autoupdatingCurrent)
    static let earlierClock = makeClock("MMM dd HH:mm", calendar: .autoupdatingCurrent, timeZone: .autoupdatingCurrent)

    private static func makeClock(_ format: String, calendar: Calendar, timeZone: TimeZone) -> DateFormatter {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.calendar = calendar
        formatter.timeZone = timeZone
        formatter.dateFormat = format
        return formatter
    }

    /// The cached formatter for the user's calendar, a new one for any other
    /// (the tests pass a UTC calendar).
    static func clockFormatter(sameDay: Bool, calendar: Calendar) -> DateFormatter {
        let format = sameDay ? "HH:mm:ss" : "MMM dd HH:mm"
        let current = Calendar.current
        guard calendar.identifier == current.identifier, calendar.timeZone == current.timeZone else {
            return makeClock(format, calendar: calendar, timeZone: calendar.timeZone)
        }
        return sameDay ? todayClock : earlierClock
    }

    /// "14:02:11" for today, "Oct 02 14:02" earlier, "" when unparseable.
    static func clockText(_ raw: String, now: Date = Date(), calendar: Calendar = .current) -> String {
        let trimmed = raw.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty,
              let stamp = fractionalStamp.date(from: trimmed) ?? plainStamp.date(from: trimmed)
        else { return "" }
        let sameDay = calendar.isDate(stamp, inSameDayAs: now)
        return clockFormatter(sameDay: sameDay, calendar: calendar).string(from: stamp)
    }
}
