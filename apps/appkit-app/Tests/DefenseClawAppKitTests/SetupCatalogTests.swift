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

    @MainActor
    func testNormalSetupModeSplitsRecommendedAndAdvancedSettings() {
        let model = SetupWorkspaceModel()

        for group in SetupCatalog.groups where !group.fields.isEmpty {
            let recommended = model.primaryFields(for: group)
            let advanced = model.advancedFields(for: group)
            let combinedIDs = Set((recommended + advanced).map(\.id))

            XCTAssertFalse(recommended.isEmpty, "\(group.id) should expose a focused recommended setup surface")
            XCTAssertEqual(combinedIDs, Set(group.fields.map(\.id)), "\(group.id) should not lose settings")
            XCTAssertTrue(Set(recommended.map(\.id)).isDisjoint(with: Set(advanced.map(\.id))), "\(group.id) should not duplicate settings")
        }
    }

    @MainActor
    func testNormalSetupModeHidesSupportWorkflowsAndAdvancedFields() {
        let model = SetupWorkspaceModel()
        let observability = try XCTUnwrap(SetupCatalog.groups.first { $0.id == "observability" })
        let gateway = try XCTUnwrap(SetupCatalog.groups.first { $0.id == "gateway" })
        let gatewayWorkflow = try XCTUnwrap(gateway.workflows.first { $0.id == "gateway-setup" })

        XCTAssertLessThan(
            model.visibleWorkflows(for: observability, includeAdvanced: false).count,
            observability.workflows.count
        )
        XCTAssertEqual(
            model.visibleWorkflows(for: observability, includeAdvanced: true).count,
            observability.workflows.count
        )
        XCTAssertLessThan(
            model.visibleWorkflowFields(for: gatewayWorkflow, includeAdvanced: false).count,
            gatewayWorkflow.fields.count
        )
        XCTAssertEqual(
            model.visibleWorkflowFields(for: gatewayWorkflow, includeAdvanced: true).count,
            gatewayWorkflow.fields.count
        )
    }
}
