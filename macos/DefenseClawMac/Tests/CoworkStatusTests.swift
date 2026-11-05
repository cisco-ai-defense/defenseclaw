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
struct CoworkStatusTests {
    static func main() {
        parsesTheCoworkObjectOfStatusJSON()
        aMissingOrMalformedCoworkKeyIsNoRow()
        notProtectedShowsTheNextStep()
        protectedShowsTheLastEventClock()
        commandRegistryHasSetupCowork()
        print("Cowork status tests passed")
    }

    private static func expect(_ condition: @autoclosure () -> Bool, _ message: String) {
        guard condition() else {
            FileHandle.standardError.write(Data("FAIL: \(message)\n".utf8))
            exit(1)
        }
    }

    private static let protectedJSON = """
    note: warming up
    {"gateway": {"state": "running"}, "cowork": {"protected": true,
     "detail": "protected, 3 calls (last 14:02:11)", "step": "", "reason_code": "",
     "last_event_at": "2026-11-05T14:02:11Z", "plugin_version": "1.0.3", "plugin_zip": "/Users/me/.defenseclaw/cowork/defenseclaw-cowork-1.0.3.zip"}}
    """

    private static func parsesTheCoworkObjectOfStatusJSON() {
        let status = CoworkStatus.parse(protectedJSON)
        expect(status?.protected == true, "protected flag")
        expect(status?.reasonCode == "", "empty reason code")
        expect(status?.pluginVersion == "1.0.3", "plugin version")
        expect(status?.pluginZip.hasSuffix("defenseclaw-cowork-1.0.3.zip") == true, "plugin zip")
        expect(status?.lastEventAt == "2026-11-05T14:02:11Z", "last event")
    }

    private static func aMissingOrMalformedCoworkKeyIsNoRow() {
        expect(CoworkStatus.parse(#"{"gateway": {}}"#) == nil, "older runtime or no Cowork: no row")
        expect(CoworkStatus.parse(#"{"cowork": null}"#) == nil, "null cowork: no row")
        expect(CoworkStatus.parse(#"{"cowork": {"detail": "x"}}"#) == nil, "no protected flag: no row")
        expect(CoworkStatus.parse("not json") == nil, "not json: no row")
        expect(CoworkStatus.parse("") == nil, "empty output: no row")
    }

    private static func notProtectedShowsTheNextStep() {
        let json = """
        {"cowork": {"protected": false, "detail": "not protected yet: no Cowork event since the plugin was built",
         "step": "upload /Users/me/.defenseclaw/cowork/defenseclaw-cowork-1.0.3.zip in Claude", "reason_code": "cowork_no_events",
         "last_event_at": null, "plugin_version": "1.0.3", "plugin_zip": null}}
        """
        guard let status = CoworkStatus.parse(json) else { expect(false, "parse"); return }
        expect(status.reasonCode == "cowork_no_events", "reason code")
        expect(status.lastEventAt.isEmpty && status.pluginZip.isEmpty, "null fields read as empty")
        let rows = status.overviewRows(home: "/Users/me")
        expect(rows.count == 2, "two rows while not protected")
        expect(rows[0].label == "Cowork" && rows[0].value == "not protected yet, no Cowork event yet", "first row: \(rows[0].value)")
        expect(rows[1].label == "Cowork next" && rows[1].value == "upload ~/.defenseclaw/cowork/defenseclaw-cowork-1.0.3.zip in Claude",
               "second row names the step with ~: \(rows[1].value)")
    }

    private static func protectedShowsTheLastEventClock() {
        guard let status = CoworkStatus.parse(protectedJSON) else { expect(false, "parse"); return }
        var utc = Calendar(identifier: .gregorian)
        utc.timeZone = TimeZone(identifier: "UTC")!
        let sameDay = utc.date(from: DateComponents(year: 2026, month: 11, day: 5, hour: 18))!
        let rows = status.overviewRows(home: "/Users/me", now: sameDay, calendar: utc)
        expect(rows.count == 1, "one row while protected")
        expect(rows[0].value == "protected, last event 14:02:11", "same-day clock: \(rows[0].value)")
        let nextDay = utc.date(from: DateComponents(year: 2026, month: 11, day: 6, hour: 9))!
        let later = status.overviewRows(home: "", now: nextDay, calendar: utc)
        expect(later[0].value == "protected, last event Nov 05 14:02", "earlier-day clock: \(later[0].value)")
        expect(CoworkStatus.clockText("garbage") == "", "unparseable stamp reads empty")
    }

    private static func commandRegistryHasSetupCowork() {
        let command = CommandRegistry.all.first { $0.title == "setup cowork" }
        expect(command?.binary == "defenseclaw" && command?.arguments == ["setup", "cowork", "--yes"], "setup cowork command")
        expect(command?.category == "setup" && command?.requiresInput == false, "setup cowork is a plain setup command")
        expect(Set(CommandRegistry.all.map(\.id)).count == CommandRegistry.all.count, "command IDs are unique")
        expect(!CommandRegistry.paletteCommands(supportedSetupCommands: []).map(\.title).contains("setup cowork"),
               "a runtime without setup cowork must not expose it")
        expect(!CommandRegistry.paletteCommands(supportedSetupCommands: nil).map(\.title).contains("setup cowork"),
               "unknown setup capability fails closed")
        expect(CommandRegistry.paletteCommands(supportedSetupCommands: ["cowork"]).map(\.title).contains("setup cowork"),
               "a runtime reporting cowork may expose it")
        expect(!CommandRegistry.paletteCommands(supportedSetupCommands: ["cowork"]).map(\.title).contains("setup amp"),
               "cowork support does not imply amp")
    }
}
