import XCTest
@testable import DefenseClawAppKit

final class YAMLConfigStoreTests: XCTestCase {
    func testRoundTripsNestedValuesWithoutDroppingExistingKeys() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let url = directory.appendingPathComponent("config.yaml")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        try """
        gateway:
          host: localhost
          api_port: 9099
        guardrail:
          enabled: false
        untouched:
          value: keep-me
        """.write(to: url, atomically: true, encoding: .utf8)

        var store = YAMLConfigStore(url: url)
        try store.load()
        XCTAssertEqual(store.string(at: "gateway.host"), "localhost")
        XCTAssertFalse(store.bool(at: "guardrail.enabled"))

        store.set("127.0.0.1", at: "gateway.host")
        store.set(true, at: "guardrail.enabled")
        store.set("DEFENSECLAW_LLM_KEY", at: "llm.api_key_env")
        try store.save()

        var reloaded = YAMLConfigStore(url: url)
        try reloaded.load()
        XCTAssertEqual(reloaded.string(at: "gateway.host"), "127.0.0.1")
        XCTAssertTrue(reloaded.bool(at: "guardrail.enabled"))
        XCTAssertEqual(reloaded.string(at: "llm.api_key_env"), "DEFENSECLAW_LLM_KEY")
        XCTAssertEqual(reloaded.string(at: "untouched.value"), "keep-me")
    }
}
