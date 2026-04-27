import XCTest
@testable import DefenseClawKit

final class HealthSnapshotTests: XCTestCase {
    func testDecodeHealthSnapshot() throws {
        let json = """
        {
            "started_at": "2026-04-02T10:00:00Z",
            "uptime_ms": 60000,
            "gateway": {"state": "running", "since": "2026-04-02T10:00:01Z"},
            "watcher": {"state": "running", "since": "2026-04-02T10:00:01Z"},
            "api": {"state": "running", "since": "2026-04-02T10:00:01Z"},
            "guardrail": {"state": "disabled", "since": "2026-04-02T10:00:00Z"},
            "telemetry": {"state": "disabled", "since": "2026-04-02T10:00:00Z"},
            "splunk": {"state": "disabled", "since": "2026-04-02T10:00:00Z"}
        }
        """.data(using: .utf8)!

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let snapshot = try decoder.decode(HealthSnapshot.self, from: json)

        XCTAssertEqual(snapshot.gateway.state, .running)
        XCTAssertEqual(snapshot.guardrail.state, .disabled)
        XCTAssertEqual(snapshot.uptimeMs, 60000)
        XCTAssertNil(snapshot.sandbox)
        XCTAssertTrue(snapshot.isHealthy)
    }

    func testDecodeCurrentSidecarHealthWithSinks() throws {
        let json = """
        {
            "started_at": "2026-04-02T10:00:00Z",
            "uptime_ms": 60000,
            "gateway": {"state": "running", "since": "2026-04-02T10:00:01Z"},
            "watcher": {"state": "running", "since": "2026-04-02T10:00:01Z"},
            "api": {"state": "running", "since": "2026-04-02T10:00:01Z"},
            "guardrail": {"state": "running", "since": "2026-04-02T10:00:01Z"},
            "telemetry": {"state": "running", "since": "2026-04-02T10:00:01Z"},
            "sinks": {"state": "disabled", "since": "2026-04-02T10:00:01Z"},
            "provenance": {"enabled": true}
        }
        """.data(using: .utf8)!

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let snapshot = try decoder.decode(HealthSnapshot.self, from: json)

        XCTAssertEqual(snapshot.gateway.state, .running)
        XCTAssertEqual(snapshot.splunk.state, .disabled)
        XCTAssertTrue(snapshot.isGatewayConnected)
        XCTAssertTrue(snapshot.isHealthy)
    }

    func testIsHealthyReturnsFalseOnError() throws {
        let json = """
        {
            "started_at": "2026-04-02T10:00:00Z",
            "uptime_ms": 1000,
            "gateway": {"state": "error", "since": "2026-04-02T10:00:01Z", "last_error": "connection refused"},
            "watcher": {"state": "running", "since": "2026-04-02T10:00:01Z"},
            "api": {"state": "running", "since": "2026-04-02T10:00:01Z"},
            "guardrail": {"state": "disabled", "since": "2026-04-02T10:00:00Z"},
            "telemetry": {"state": "disabled", "since": "2026-04-02T10:00:00Z"},
            "splunk": {"state": "disabled", "since": "2026-04-02T10:00:00Z"}
        }
        """.data(using: .utf8)!

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let snapshot = try decoder.decode(HealthSnapshot.self, from: json)

        XCTAssertFalse(snapshot.isHealthy)
        XCTAssertEqual(snapshot.gateway.lastError, "connection refused")
    }

    func testSeverityComparison() {
        XCTAssertTrue(Severity.low < Severity.high)
        XCTAssertTrue(Severity.none < Severity.info)
        XCTAssertTrue(Severity.critical > Severity.medium)
    }
}
