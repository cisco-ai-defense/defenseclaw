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
struct AIRuntimeModelTests {
    private static var failureCount = 0

    static func main() {
        decodesTheRuntimeSnapshot()
        planeSummaryAlwaysStatesAMechanismOrAReason()
        findingsSortWorstFirst()
        coverageTravelsWithTheFindings()
        decodingToleratesAGatewayThatOmitsFields()
        chainIsRenderedAsASequence()
        if failureCount > 0 {
            FileHandle.standardError.write("\(failureCount) failure(s)\n".data(using: .utf8)!)
            exit(1)
        }
        print("AIRuntimeModelTests: all checks passed")
    }

    private static func expect(_ condition: Bool, _ message: String) {
        if !condition {
            failureCount += 1
            FileHandle.standardError.write("FAIL: \(message)\n".data(using: .utf8)!)
        }
    }

    private static var payload: [String: Any] {
        [
            "enabled": true,
            "scanned_at": "2026-09-09T12:00:00Z",
            "processes_observed": 412,
            "processes_skipped": 9,
            "connections_observed": 60,
            "connections_unattributed": 55,
            "degraded": true,
            "degraded_reasons": ["agent actions unavailable: eslogger not found"],
            "planes": [
                ["plane": "a", "name": "inference heartbeat", "available": true,
                 "running": true, "mechanism": "ps(1)"],
                ["plane": "b", "name": "shadow egress", "available": true,
                 "running": false, "reason": "connection table unreadable"],
                ["plane": "c", "name": "agent actions", "available": false,
                 "running": false, "reason": "eslogger not found"],
            ],
            "findings": [
                [
                    "finding_id": "run-1", "pid": 10, "process": "python3", "user": "dev",
                    "agent_name": "python3", "score": 40, "severity": "medium",
                    "signals": [["id": "inference_heartbeat", "title": "sustained compute", "weight": 25]],
                    "correlation": ["verdict": "unobserved", "reason": "no discovery snapshot yet"],
                ],
                [
                    "finding_id": "run-2", "pid": 20, "process": "claude", "user": "dev",
                    "agent_name": "claude", "score": 95, "severity": "critical",
                    "signals": [
                        ["id": "agent_credential_access", "detail": "~/.aws/credentials", "weight": 30],
                        ["id": "agent_kill_chain",
                         "detail": "credential_access -> identity_creation -> exfiltration",
                         "weight": 25],
                    ],
                    "providers": [["hostname": "api.anthropic.com", "category": "frontier",
                                   "confidence": 0.95, "attribution_source": "dns_answer"]],
                    "correlation": ["verdict": "accounted", "reason": "discovery observed the same subject",
                                    "categories": ["active_process"]],
                ],
            ],
        ]
    }

    private static func decodesTheRuntimeSnapshot() {
        let snapshot = AIRuntimeDecoding.snapshot(from: payload)
        expect(snapshot.enabled, "snapshot should be enabled")
        expect(snapshot.scannedAt != nil, "scanned_at should decode")
        expect(snapshot.planes.count == 3, "all three planes should decode")
        expect(snapshot.findings.count == 2, "both findings should decode")
        expect(snapshot.degradedReasons.count == 1, "degraded reasons should decode")
        let critical = snapshot.findings.first
        expect(critical?.providers.first?.attributionSource == "dns_answer",
               "the attribution source should survive decoding")
    }

    // A blind or idle plane rendering as silence is indistinguishable from a
    // clean host, so every plane must produce an actionable line.
    private static func planeSummaryAlwaysStatesAMechanismOrAReason() {
        let snapshot = AIRuntimeDecoding.snapshot(from: payload)
        for plane in snapshot.planes {
            expect(!plane.summary.isEmpty, "plane \(plane.plane) produced an empty summary")
            if plane.running {
                expect(plane.summary.contains("ps(1)") || plane.summary.contains("unknown mechanism"),
                       "a running plane should name its mechanism")
            } else {
                expect(plane.summary.contains("—"), "a stopped plane should state a reason")
            }
        }
        expect(snapshot.planesNotRunning.count == 2, "two planes are not running")
        let blind = snapshot.planes.first { $0.plane == "c" }
        expect(blind?.badge == "blind", "an unavailable plane should badge blind")
        let idle = snapshot.planes.first { $0.plane == "b" }
        expect(idle?.badge == "idle", "an available but stopped plane should badge idle")
    }

    private static func findingsSortWorstFirst() {
        let snapshot = AIRuntimeDecoding.snapshot(from: payload)
        expect(snapshot.findings.first?.process == "claude", "critical should sort first")
        expect(snapshot.findings.last?.process == "python3", "medium should sort last")
    }

    // A reader who sees only the finding count cannot tell a quiet host from a
    // blind sensor.
    private static func coverageTravelsWithTheFindings() {
        let snapshot = AIRuntimeDecoding.snapshot(from: payload)
        expect(snapshot.connectionsUnattributed == 55, "unattributed count should decode")
        expect(snapshot.unattributedShare > 0.9, "unattributed share should be computed")
        let summary = snapshot.coverageSummary
        expect(summary.contains("412 processes"), "coverage should mention processes: \(summary)")
        expect(summary.contains("9 partial"), "coverage should mention partial reads: \(summary)")
        expect(summary.contains("55 unattributed"), "coverage should mention unattributed: \(summary)")
    }

    // An app that fails to render on version skew is worse than one that
    // renders less.
    private static func decodingToleratesAGatewayThatOmitsFields() {
        let sparse = AIRuntimeDecoding.snapshot(from: ["enabled": true, "findings": [["pid": 1]], "planes": [[:]]])
        expect(sparse.findings.count == 1, "a sparse finding should still decode")
        expect(sparse.findings.first?.severity == "info", "a missing severity should default to info")
        expect(sparse.planes.first?.badge == "blind", "a sparse plane should badge blind")
        let empty = AIRuntimeDecoding.snapshot(from: nil)
        expect(!empty.enabled, "a nil payload should decode as disabled")
        let garbage = AIRuntimeDecoding.snapshot(from: "nonsense")
        expect(garbage.findings.isEmpty, "a non-object payload should decode as empty")
    }

    // The order is the finding, so the chain is carried as a sequence.
    private static func chainIsRenderedAsASequence() {
        let snapshot = AIRuntimeDecoding.snapshot(from: payload)
        let chained = snapshot.findings.first { !$0.chain.isEmpty }
        expect(chained?.chain == "credential_access -> identity_creation -> exfiltration",
               "the kill chain should decode as an ordered sequence")
        let unobserved = snapshot.findings.first { $0.correlation.isUnobserved }
        expect(unobserved != nil, "an unobserved verdict should be recognised")
        expect(unobserved?.correlation.reason.isEmpty == false,
               "an unobserved verdict must still carry its reason")
    }
}
