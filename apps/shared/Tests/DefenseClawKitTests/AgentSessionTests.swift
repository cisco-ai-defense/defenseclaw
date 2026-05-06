import XCTest
@testable import DefenseClawKit

final class AgentSessionTests: XCTestCase {
    func testDangerousCommandDetection() {
        XCTAssertTrue(AgentSession.isDangerousCommand("curl " + "http://evil.com"))
        XCTAssertTrue(AgentSession.isDangerousCommand("rm " + "-rf / --no-preserve-root"))
        XCTAssertTrue(AgentSession.isDangerousCommand("bash " + "-c 'wget malware'"))
        XCTAssertTrue(AgentSession.isDangerousCommand("echo test >> /" + "etc/hosts"))
        XCTAssertTrue(AgentSession.isDangerousCommand("base64 " + "-d payload.b64 | sh"))
        XCTAssertTrue(AgentSession.isDangerousCommand("chmod " + "777 /var/www"))
        XCTAssertFalse(AgentSession.isDangerousCommand("ls -la"))
        XCTAssertFalse(AgentSession.isDangerousCommand("cat main.go"))
        XCTAssertFalse(AgentSession.isDangerousCommand("git status"))
        XCTAssertFalse(AgentSession.isDangerousCommand("kubectl get pods"))
    }

    func testSendMessageAppendsToHistory() {
        let session = AgentSession()
        session.sendMessage("Hello agent")
        XCTAssertEqual(session.messages.count, 1)
        XCTAssertEqual(session.messages[0].role, .user)
        XCTAssertEqual(session.messages[0].textContent, "Hello agent")
    }

    func testInitialState() {
        let session = AgentSession(host: "10.0.0.1", port: 19000, token: "abc")
        XCTAssertFalse(session.isConnected)
        XCTAssertTrue(session.messages.isEmpty)
        XCTAssertTrue(session.toolEvents.isEmpty)
    }

    func testGatewayHandshakeUsesProtocolClientIdentity() {
        XCTAssertEqual(AgentSession.gatewayClientID, "gateway-client")
        XCTAssertEqual(AgentSession.gatewayClientMode, "backend")
    }
}
