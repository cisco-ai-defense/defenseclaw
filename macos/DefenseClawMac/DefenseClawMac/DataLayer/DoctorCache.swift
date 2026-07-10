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

// Reader for <data_dir>/doctor_cache.json — the cache `defenseclaw doctor`
// rewrites atomically at the end of every run. The TUI (and this app) never
// runs doctor automatically; the cache is the at-launch source for the DOCTOR
// box, the keys row, and the doctor-derived attention notices.

import Foundation

struct DoctorCache: Sendable, Equatable {
    struct Check: Sendable, Equatable, Identifiable {
        var status: String   // pass | fail | warn | skip
        var label: String
        var detail: String
        var id: String { "\(status)-\(label)" }
    }

    static let stalenessWindow: TimeInterval = 15 * 60

    var capturedAt: Date?
    var passed = 0
    var failed = 0
    var warned = 0
    var skipped = 0
    var checks: [Check] = []

    var isEmpty: Bool {
        capturedAt == nil && passed == 0 && failed == 0 && warned == 0
            && skipped == 0 && checks.isEmpty
    }

    /// Negative when never captured (TUI age() returns -1s).
    func age(now: Date = Date()) -> TimeInterval {
        guard let capturedAt else { return -1 }
        return now.timeIntervalSince(capturedAt)
    }

    func isStale(now: Date = Date()) -> Bool {
        guard capturedAt != nil else { return true }
        return age(now: now) > Self.stalenessWindow
    }

    /// All fail checks (file order), then all warn checks, truncated.
    func topFailures(_ limit: Int) -> [Check] {
        let fails = checks.filter { $0.status == "fail" }
        let warns = checks.filter { $0.status == "warn" }
        return Array((fails + warns).prefix(limit))
    }

    /// Env-var names from failing "credential <NAME>" checks, in file order.
    var missingRequiredCredentials: [String] {
        checks.compactMap { check in
            guard check.status == "fail", check.label.hasPrefix("credential ") else { return nil }
            let name = String(check.label.dropFirst("credential ".count))
                .trimmingCharacters(in: .whitespaces)
            return name.isEmpty ? nil : name
        }
    }

    /// TUI format_age: never / just now / Ns ago / Nm ago / Nh ago / Nd ago.
    func ageLabel(now: Date = Date()) -> String {
        guard capturedAt != nil else { return "never" }
        // Truncate before comparing (TUI int()) so sub-second clock skew
        // after a fresh run reads "just now", not "never".
        guard let seconds = DCSafeNumbers.intTruncating(age(now: now)) else { return "never" }
        if seconds < 0 { return "never" }
        if seconds < 30 { return "just now" }
        if seconds < 60 { return "\(seconds)s ago" }
        if seconds < 3600 { return "\(seconds / 60)m ago" }
        if seconds < 86_400 { return "\(seconds / 3600)h ago" }
        return "\(seconds / 86_400)d ago"
    }

    /// Load <data_dir>/doctor_cache.json; nil when missing/unparseable
    /// (callers keep their previous value — TUI keeps last-good on error).
    static func load(dataDirectory: URL = ConfigStore.dataDirectory) -> DoctorCache? {
        let url = dataDirectory.appendingPathComponent("doctor_cache.json")
        guard let data = try? Data(contentsOf: url),
              let dict = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
        else { return nil }
        var cache = DoctorCache()
        cache.passed = (dict["passed"] as? Int) ?? 0
        cache.failed = (dict["failed"] as? Int) ?? 0
        cache.warned = (dict["warned"] as? Int) ?? 0
        cache.skipped = (dict["skipped"] as? Int) ?? 0
        cache.capturedAt = DCDates.parse(dict["captured_at"])
        cache.checks = ((dict["checks"] as? [Any]) ?? []).compactMap { item in
            guard let row = item as? [String: Any] else { return nil }
            return Check(
                status: (row["status"] as? String) ?? "",
                label: (row["label"] as? String) ?? "",
                detail: (row["detail"] as? String) ?? ""
            )
        }
        return cache
    }
}
