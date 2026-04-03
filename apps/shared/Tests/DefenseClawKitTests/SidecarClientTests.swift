import XCTest
@testable import DefenseClawKit

final class SidecarClientTests: XCTestCase {
    func testBaseURLConstruction() {
        let _ = SidecarClient(host: "127.0.0.1", port: 18790)
        let _ = SidecarClient(host: "10.200.0.1", port: 19000)
    }

    func testSidecarErrorDescription() {
        let err = SidecarError.requestFailed(endpoint: "/health")
        XCTAssertEqual(err.errorDescription, "Sidecar request failed: /health")

        let underlying = NSError(domain: "test", code: 1)
        let decErr = SidecarError.decodingFailed(endpoint: "/skills", underlying: underlying)
        XCTAssertTrue(decErr.errorDescription!.contains("/skills"))
    }
}
