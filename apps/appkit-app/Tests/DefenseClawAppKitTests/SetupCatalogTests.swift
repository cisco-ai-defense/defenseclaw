import XCTest
@testable import DefenseClawAppKit

final class SetupCatalogTests: XCTestCase {
    func testCatalogIncludesTUIParityGroups() {
        let ids = Set(SetupCatalog.groups.map(\.id))
        for required in ["llm", "gateway", "scanners", "guardrail", "observability", "webhooks", "enforcement", "sandbox"] {
            XCTAssertTrue(ids.contains(required), "Missing setup group \(required)")
        }
    }

    func testCatalogIncludesRequestedSetupWorkflows() {
        let workflowIDs = Set(SetupCatalog.groups.flatMap(\.workflows).map(\.id))
        for required in [
            "skill-scanner",
            "mcp-scanner",
            "guardrail-setup",
            "obs-splunk-o11y",
            "obs-splunk-hec",
            "obs-datadog",
            "webhook-slack",
            "webhook-pagerduty",
            "webhook-webex",
            "webhook-generic",
            "sandbox-setup"
        ] {
            XCTAssertTrue(workflowIDs.contains(required), "Missing workflow \(required)")
        }
    }
}
