import XCTest
@testable import DefenseClawKit

/// Live integration test — requires sidecar running on localhost:18970
final class SidecarLiveTest: XCTestCase {
    let client = SidecarClient()

    func testHealth() async throws {
        let h = try await client.health()
        XCTAssertGreaterThan(h.uptimeMs, 0)
        print("✅ health: uptime=\(h.uptimeMs) gateway=\(h.gateway.state)")
    }

    func testAlerts() async throws {
        let alerts = try await client.alerts()
        print("✅ alerts: \(alerts.count) items")
    }

    func testSkills() async {
        // May fail if gateway not connected — that's OK
        do {
            let skills = try await client.skills()
            print("✅ skills: \(skills.count) items")
        } catch {
            print("⚠️ skills: \(error.localizedDescription) (expected if gateway offline)")
        }
    }

    func testMCPServers() async throws {
        let mcps = try await client.mcpServers()
        print("✅ mcps: \(mcps.count) items")
    }

    func testBlockedList() async throws {
        let blocked = try await client.blockedList()
        print("✅ blocked: \(blocked.count) items")
    }

    func testAllowedList() async throws {
        let allowed = try await client.allowedList()
        print("✅ allowed: \(allowed.count) items")
    }

    func testGuardrailConfig() async throws {
        let gc = try await client.guardrailConfig()
        print("✅ guardrail config: mode=\(gc.mode) scanner_mode=\(gc.scannerMode)")
    }

    func testPolicyShow() async {
        do {
            let policy = try await client.policyShow()
            print("✅ policy show: \(policy.prefix(50))...")
        } catch {
            print("⚠️ policy show: \(error.localizedDescription)")
        }
    }

    func testToolsCatalog() async {
        do {
            let tools = try await client.toolsCatalog()
            print("✅ tools catalog: \(tools.count) items")
        } catch {
            print("⚠️ tools catalog: \(error.localizedDescription) (expected if gateway offline)")
        }
    }
}
