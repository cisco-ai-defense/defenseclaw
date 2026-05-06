import XCTest
@testable import DefenseClawKit

final class SidecarClientTests: XCTestCase {
    func testBaseURLConstruction() {
        let _ = SidecarClient(host: "127.0.0.1", port: 18970)
        let _ = SidecarClient(host: "10.200.0.1", port: 19000)
    }

    func testSidecarErrorDescription() {
        let err = SidecarError.requestFailed(endpoint: "/health")
        XCTAssertEqual(err.errorDescription, "Sidecar request failed: /health")

        let underlying = NSError(domain: "test", code: 1)
        let decErr = SidecarError.decodingFailed(endpoint: "/skills", underlying: underlying)
        XCTAssertTrue(decErr.errorDescription!.contains("/skills"))
    }

    func testScanResultResponseAcceptsEnvelopeAndBareResult() throws {
        let resultJSON = """
        {
            "id": "scan-1",
            "target": "/tmp/skill",
            "scan_type": "skill",
            "severity": "LOW",
            "findings": [],
            "scanned_at": "2026-04-02T10:00:00Z"
        }
        """
        let envelopeJSON = #"{"result": \#(resultJSON)}"#
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601

        let envelope = try decoder.decode(ScanResultResponse.self, from: envelopeJSON.data(using: .utf8)!)
        let bare = try decoder.decode(ScanResultResponse.self, from: resultJSON.data(using: .utf8)!)

        XCTAssertEqual(envelope.result.target, "/tmp/skill")
        XCTAssertEqual(bare.result.scanType, "skill")
    }

    func testScanResultAcceptsCLIPluginScannerShape() throws {
        let resultJSON = """
        {
            "scanner": "plugin-scanner",
            "target": "/tmp/plugin",
            "timestamp": "2026-04-02T10:00:00+00:00",
            "findings": [
                {
                    "id": "f-1",
                    "rule_id": "PLUGIN-INSTALL",
                    "severity": "HIGH",
                    "title": "Install script",
                    "description": "Plugin has an install script",
                    "remediation": "Review before enabling"
                }
            ],
            "duration_ms": 10
        }
        """

        let result = try JSONDecoder().decode(ScanResult.self, from: resultJSON.data(using: .utf8)!)

        XCTAssertEqual(result.scanType, "plugin-scanner")
        XCTAssertEqual(result.overallSeverity, .high)
        XCTAssertEqual(result.findings.first?.rule, "PLUGIN-INSTALL")
    }

    func testPluginListAcceptsCLIShape() throws {
        let pluginJSON = """
        {
            "id": "xai",
            "name": "@openclaw/xai-plugin",
            "description": "XAI provider",
            "version": "1.0.0",
            "source": "openclaw",
            "status": "enabled",
            "enabled": true
        }
        """

        let plugin = try JSONDecoder().decode(Plugin.self, from: pluginJSON.data(using: .utf8)!)

        XCTAssertEqual(plugin.id, "xai")
        XCTAssertEqual(plugin.name, "@openclaw/xai-plugin")
        XCTAssertEqual(plugin.pluginDescription, "XAI provider")
        XCTAssertTrue(plugin.enabled)
    }
}
