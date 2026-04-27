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

    func testStructuredYamlRoundTripSupportsRichEditing() throws {
        var document = try StructuredPolicyDocumentCodec.parse(
            content: "default_action: deny\nallowlist:\n  domains:\n    - api.example.com\n",
            kind: .yaml
        )

        guard case .object(var entries) = document,
              let actionIndex = entries.firstIndex(where: { $0.key == "default_action" }) else {
            return XCTFail("Expected YAML object with default_action")
        }

        entries[actionIndex].value = .string("allow")
        document = .object(entries)

        let yaml = try StructuredPolicyDocumentCodec.serialize(document, kind: .yaml)
        XCTAssertEqual(TextFileWorkspace.validate(content: yaml, kind: .yaml).state, .valid)
        XCTAssertTrue(yaml.contains("default_action: allow"))
    }

    func testStructuredJsonRoundTripSupportsRichEditing() throws {
        var document = try StructuredPolicyDocumentCodec.parse(
            content: #"{"guardrail":{"enabled":true,"mode":"observe"}}"#,
            kind: .json
        )

        guard case .object(var entries) = document,
              let guardrailIndex = entries.firstIndex(where: { $0.key == "guardrail" }),
              case .object(var guardrailEntries) = entries[guardrailIndex].value,
              let modeIndex = guardrailEntries.firstIndex(where: { $0.key == "mode" }) else {
            return XCTFail("Expected nested JSON object with guardrail.mode")
        }

        guardrailEntries[modeIndex].value = .string("action")
        entries[guardrailIndex].value = .object(guardrailEntries)
        document = .object(entries)

        let json = try StructuredPolicyDocumentCodec.serialize(document, kind: .json)
        XCTAssertEqual(TextFileWorkspace.validate(content: json, kind: .json).state, .valid)
        XCTAssertTrue(json.contains(#""mode" : "action""#))
    }

    func testRegoRichDocumentRoundTripSupportsPolicySections() {
        var document = RegoPolicyDocumentCodec.parse("""
        package defenseclaw.guardrail

        import future.keywords.if

        allow if {
            input.safe
        }
        """)

        document.imports.append("data.defenseclaw.helpers")
        document.rules.append(RegoRuleBlock(title: "deny", body: "deny if {\n    input.risky\n}"))

        let rego = RegoPolicyDocumentCodec.serialize(document)
        XCTAssertEqual(TextFileWorkspace.validate(content: rego, kind: .rego).state, .warning)
        XCTAssertTrue(rego.contains("package defenseclaw.guardrail"))
        XCTAssertTrue(rego.contains("import data.defenseclaw.helpers"))
        XCTAssertTrue(rego.contains("deny if"))
    }
}
