import XCTest
@testable import DefenseClawKit

final class ConfigManagerTests: XCTestCase {
    var tempDir: URL!
    var configPath: String!

    override func setUp() {
        super.setUp()
        tempDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try! FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        configPath = tempDir.appendingPathComponent("config.yaml").path
    }

    override func tearDown() {
        try? FileManager.default.removeItem(at: tempDir)
        super.tearDown()
    }

    func testLoadAndSaveRoundTrip() throws {
        let manager = ConfigManager(configPath: configPath)
        var config = AppConfig()
        config.claw = ClawConfig()
        config.claw?.mode = "openclaw"
        config.gateway = GatewayFullConfig()
        config.gateway?.host = "127.0.0.1"
        config.gateway?.port = 18789
        config.gateway?.apiPort = 18790
        config.guardrail = GuardrailFullConfig()
        config.guardrail?.enabled = false
        config.guardrail?.mode = "observe"

        try manager.save(config)
        XCTAssertTrue(manager.exists)

        let loaded = try manager.load()
        XCTAssertEqual(loaded.claw?.mode, "openclaw")
        XCTAssertEqual(loaded.gateway?.host, "127.0.0.1")
        XCTAssertEqual(loaded.gateway?.port, 18789)
        XCTAssertEqual(loaded.guardrail?.enabled, false)
        XCTAssertEqual(loaded.guardrail?.mode, "observe")
    }

    func testExistsReturnsFalseWhenMissing() {
        let manager = ConfigManager(configPath: tempDir.appendingPathComponent("nonexistent.yaml").path)
        XCTAssertFalse(manager.exists)
    }

    func testFilePermissions() throws {
        let manager = ConfigManager(configPath: configPath)
        try manager.save(AppConfig())
        let attrs = try FileManager.default.attributesOfItem(atPath: configPath)
        let perms = attrs[.posixPermissions] as! Int
        XCTAssertEqual(perms, 0o600)
    }
}
