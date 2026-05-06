import XCTest
@testable import DefenseClawKit

final class LaunchAgentManagerTests: XCTestCase {
    func testPlistContentHasRequiredKeys() {
        let manager = LaunchAgentManager(sidecarBinary: "/usr/local/bin/defenseclaw-gateway")
        let plist = manager.plistContent()
        XCTAssertEqual(plist["Label"] as? String, "com.defenseclaw.sidecar")
        XCTAssertEqual(plist["RunAtLoad"] as? Bool, true)
        XCTAssertEqual(plist["KeepAlive"] as? Bool, true)
        let args = plist["ProgramArguments"] as? [String]
        XCTAssertEqual(args?.first, "/usr/local/bin/defenseclaw-gateway")
        XCTAssertTrue(args?.contains("start") ?? false)
        XCTAssertTrue(args?.contains("--foreground") ?? false)
    }

    func testPlistContentIncludesLogPaths() {
        let manager = LaunchAgentManager()
        let plist = manager.plistContent()
        let stdout = plist["StandardOutPath"] as? String ?? ""
        let stderr = plist["StandardErrorPath"] as? String ?? ""
        XCTAssertTrue(stdout.contains(".defenseclaw/sidecar.stdout.log"))
        XCTAssertTrue(stderr.contains(".defenseclaw/sidecar.stderr.log"))
    }

    func testLabel() {
        XCTAssertEqual(LaunchAgentManager.label, "com.defenseclaw.sidecar")
    }
}
