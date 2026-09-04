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
struct StructuredDetailParserTests {
    static func main() {
        leadingRedactionFallsBackToRawDetails()
        safeMetadataSkipsRedactionAttributes()
        redactedValueRemainsOneField()
        quotedValuesRemainIntact()
        prettyJSONStillFormatsStructuredPayloads()
        print("StructuredDetailParserTests passed")
    }

    private static func leadingRedactionFallsBackToRawDetails() {
        let details = reportedDriftDetails
        expect(StructuredDetailParser.pairs(details).isEmpty,
               "a leading redaction placeholder must not become a key/value grid")
    }

    private static func safeMetadataSkipsRedactionAttributes() {
        let metadata = StructuredDetailParser.safeMetadataPairs(reportedDriftDetails)
        expect(metadata.count == 1, "only allowlisted top-level metadata is extracted")
        expect(metadata.first?.0 == "Rule IDs", "rule_ids receives a readable label")
        expect(metadata.first?.1 == "SRC-CHILD-PROC,STRUCT-SCRIPT,JSON-SEC-GENERIC",
               "rule identifiers are preserved")
        expect(!metadata.contains { $0.0 == "Len" || $0.0 == "Sha" },
               "redaction attributes never become metadata rows")
    }

    private static func redactedValueRemainsOneField() {
        let pairs = StructuredDetailParser.pairs(
            "payload=<redacted len=174 sha=7d7f6a97> connector=codex reason=\"policy denied command\""
        )
        expect(pairs.count == 3, "redacted and quoted values stay grouped")
        expect(pairs[0].0 == "Payload", "payload key is parsed")
        expect(pairs[0].1 == "redacted · 174 bytes · sha:7d7f6a97",
               "redaction placeholder is summarized without losing its boundary")
        expect(pairs[1].1 == "codex", "following fields remain parseable")
        expect(pairs[2].1 == "policy denied command", "quoted spaces remain in one value")
    }

    private static func quotedValuesRemainIntact() {
        let pairs = StructuredDetailParser.pairs("action=block message='unsafe command detected'")
        expect(pairs.count == 2, "quoted record parses completely")
        expect(pairs[1].1 == "unsafe command detected", "single-quoted values retain spaces")
    }

    private static func prettyJSONStillFormatsStructuredPayloads() {
        let formatted = StructuredDetailParser.prettyJSON("{\"b\":2,\"a\":1}")
        expect(formatted.contains("\n"), "JSON is pretty printed")
        expect(formatted.range(of: "\"a\"")?.lowerBound ?? formatted.endIndex
               < formatted.range(of: "\"b\"")?.lowerBound ?? formatted.endIndex,
               "JSON keys are sorted")
    }

    private static let reportedDriftDetails = """
    <redacted len=13291 sha=20e286f0> rule_ids=SRC-CHILD-PROC,STRUCT-SCRIPT,JSON-SEC-GENERIC <redacted len=76 sha=757a90e1> <redacted len=174 sha=7d7f6a97>
    """

    private static func expect(_ condition: @autoclosure () -> Bool, _ message: String) {
        guard condition() else {
            fputs("FAILED: \(message)\n", stderr)
            exit(1)
        }
    }
}
