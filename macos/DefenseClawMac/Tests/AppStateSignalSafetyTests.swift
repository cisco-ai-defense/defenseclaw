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
struct AppStateSignalSafetyTests {
    static func main() {
        distinguishesMissingPresenceFromReportedZero()
        requiresHighReportedPresenceForConnectorDiscovery()
        includesPrimaryConnectorInFilterRoster()
        deduplicatesPrimaryConnectorCaseInsensitively()
        preservesLegacyRosterFallback()
        print("App-state signal and connector roster safety tests passed")
    }

    private static func distinguishesMissingPresenceFromReportedZero() {
        expect(
            !AIPresenceAxis.wasReported(rawScore: nil, band: ""),
            "missing legacy presence axis"
        )
        expect(
            !AIPresenceAxis.wasReported(rawScore: NSNull(), band: ""),
            "null legacy presence axis"
        )
        expect(
            AIPresenceAxis.wasReported(rawScore: 0.0, band: ""),
            "explicit numeric zero is reported"
        )
        expect(
            AIPresenceAxis.wasReported(rawScore: nil, band: "very_low"),
            "omitempty numeric zero retains its reported band"
        )
    }

    private static func requiresHighReportedPresenceForConnectorDiscovery() {
        expect(
            makeSignal(presenceScore: 0, presenceAxisReported: false)
                .hasEligiblePresence(minimum: 0.8),
            "older payload without presence axis remains compatible"
        )
        expect(
            !makeSignal(presenceScore: 0, presenceAxisReported: true)
                .hasEligiblePresence(minimum: 0.8),
            "reported zero presence is rejected"
        )
        expect(
            !makeSignal(presenceScore: 0.79, presenceAxisReported: true)
                .hasEligiblePresence(minimum: 0.8),
            "reported low presence is rejected"
        )
        expect(
            makeSignal(presenceScore: 0.8, presenceAxisReported: true)
                .hasEligiblePresence(minimum: 0.8),
            "reported high presence is accepted"
        )
    }

    private static func includesPrimaryConnectorInFilterRoster() {
        let names = ActiveConnectorRoster.names(
            configured: ["codex"],
            legacy: nil,
            live: ["cursor"],
            primary: "claudecode"
        )
        expect(names == ["codex", "cursor", "claudecode"], "primary connector is filterable")

        let primaryOnly = ActiveConnectorRoster.names(
            configured: [],
            legacy: nil,
            live: [],
            primary: "openclaw"
        )
        expect(primaryOnly == ["openclaw"], "primary-only legacy health roster")
    }

    private static func deduplicatesPrimaryConnectorCaseInsensitively() {
        let names = ActiveConnectorRoster.names(
            configured: ["Codex"],
            legacy: nil,
            live: ["Cursor"],
            primary: "cursor"
        )
        expect(names == ["Codex", "Cursor"], "primary duplicate is omitted")
    }

    private static func preservesLegacyRosterFallback() {
        expect(
            ActiveConnectorRoster.names(
                configured: [],
                legacy: "zeptoclaw",
                live: ["cursor"],
                primary: nil
            ) == ["zeptoclaw", "cursor"],
            "legacy configured connector leads"
        )
        expect(
            ActiveConnectorRoster.names(
                configured: ["codex"],
                legacy: "zeptoclaw",
                live: [],
                primary: nil
            ) == ["codex"],
            "populated roster ignores stale singular config"
        )
    }

    private static func makeSignal(
        presenceScore: Double,
        presenceAxisReported: Bool
    ) -> AISignal {
        AISignal(
            state: "active",
            product: "Codex",
            vendor: "OpenAI",
            category: "supported_connector",
            detector: "test",
            version: "",
            ecosystem: "",
            componentName: "",
            source: "test",
            confidence: 0.95,
            identityScore: 0.95,
            identityBand: "very_high",
            presenceScore: presenceScore,
            presenceBand: presenceAxisReported ? "very_low" : "",
            presenceAxisReported: presenceAxisReported,
            firstSeen: nil,
            lastSeen: nil,
            lastActive: nil
        )
    }

    private static func expect(_ condition: @autoclosure () -> Bool, _ label: String) {
        guard condition() else {
            fputs("FAILED: \(label)\n", stderr)
            exit(1)
        }
    }
}
