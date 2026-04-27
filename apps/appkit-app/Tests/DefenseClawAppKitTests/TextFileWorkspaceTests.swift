import XCTest
@testable import DefenseClawAppKit

final class TextFileWorkspaceTests: XCTestCase {
    func testValidatesStructuredFileFormats() {
        XCTAssertEqual(
            TextFileWorkspace.validate(content: "gateway:\n  api_port: 18970\n", kind: .yaml).state,
            .valid
        )
        XCTAssertEqual(
            TextFileWorkspace.validate(content: #"{"gateway":{"api_port":18970}}"#, kind: .json).state,
            .valid
        )
        XCTAssertEqual(
            TextFileWorkspace.validate(content: "package defenseclaw\nallow { true }\n", kind: .rego).state,
            .warning
        )
    }

    func testRejectsInvalidStructuredFiles() {
        XCTAssertEqual(
            TextFileWorkspace.validate(content: "gateway:\n  api_port: [", kind: .yaml).state,
            .invalid
        )
        XCTAssertEqual(
            TextFileWorkspace.validate(content: #"{"gateway":]"#, kind: .json).state,
            .invalid
        )
        XCTAssertEqual(
            TextFileWorkspace.validate(content: "allow { true }\n", kind: .rego).state,
            .invalid
        )
    }

    func testSavesAndLoadsManagedTextFile() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let url = directory.appendingPathComponent("config.yaml")
        let file = ManagedTextFile(
            url: url,
            relativePath: "config.yaml",
            category: "Primary Config",
            group: "DefenseClaw",
            source: .runtime
        )
        let content = "gateway:\n  api_bind: 127.0.0.1\n  api_port: 18970\n"

        try TextFileWorkspace.save(content, to: file)

        XCTAssertEqual(try TextFileWorkspace.load(file), content)
        XCTAssertEqual(TextFileWorkspace.validate(content: content, kind: file.kind).state, .valid)
    }
}
