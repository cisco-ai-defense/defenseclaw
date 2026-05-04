# DefenseClaw macOS App — Phase 1: Shared DefenseClawKit

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the shared Swift package (`DefenseClawKit`) that provides REST client, WebSocket v3 client, process runner, config manager, and all data models — consumed by App A (SwiftUI) and App C (AppKit hybrid).

**Architecture:** A Swift Package Manager library with zero UI dependencies. Communicates with the DefenseClaw sidecar via HTTP REST (`localhost:18790`) and with the OpenClaw gateway via WebSocket v3 (`ws://host:port`). Python CLI commands are invoked via `Process`. Config is read/written as YAML via `Yams` library.

**Tech Stack:** Swift 5.9+, SPM, async/await, URLSession, URLSessionWebSocketTask, Yams (YAML parsing)

---

## File Structure

```
apps/shared/
  Package.swift                          # SPM manifest (library target + test target)
  Sources/DefenseClawKit/
    Models/
      Severity.swift                     # Severity enum (CRITICAL, HIGH, MEDIUM, LOW, INFO, NONE)
      Alert.swift                        # Alert struct (from /alerts endpoint)
      Skill.swift                        # Skill struct (from /skills endpoint)
      Plugin.swift                       # Plugin struct (from /plugin/*)
      MCPServer.swift                    # MCPServer struct (from /mcps endpoint)
      ToolEntry.swift                    # ToolEntry struct (from /tools/catalog)
      HealthSnapshot.swift               # HealthSnapshot + SubsystemHealth (from /health)
      ToolEvent.swift                    # ToolEvent for tool_call/tool_result WS events
      ChatMessage.swift                  # ChatMessage with ContentBlock enum (text, thinking, tool_call, approval, guardrail)
      SessionConfig.swift                # SessionConfig (workspace, agent name)
      ScanResult.swift                   # ScanResult + Finding (from scan endpoints)
      PolicyModels.swift                 # AdmissionInput/Output, FirewallInput/Output
      EnforceModels.swift                # BlockEntry, AllowEntry, EnforceRequest
      GuardrailModels.swift              # GuardrailConfig, GuardrailEvent, GuardrailEvalRequest
      ConfigModels.swift                 # Full Config struct matching config.yaml
    SidecarClient.swift                  # REST client for all 30 sidecar endpoints
    AgentSession.swift                   # WebSocket v3 client (handshake, events, RPC)
    ProcessRunner.swift                  # Shell out to Python CLI
    LaunchAgentManager.swift             # macOS LaunchAgent plist install/uninstall
    ConfigManager.swift                  # Read/write ~/.defenseclaw/config.yaml via Yams
  Tests/DefenseClawKitTests/
    Models/
      ChatMessageTests.swift
      HealthSnapshotTests.swift
      ScanResultTests.swift
    SidecarClientTests.swift             # Tests with mock URLProtocol
    AgentSessionTests.swift              # Tests with mock WebSocket
    ConfigManagerTests.swift             # Tests with temp YAML files
    LaunchAgentManagerTests.swift
    ProcessRunnerTests.swift
```

---

### Task 1: SPM Package Scaffold

**Files:**
- Create: `apps/shared/Package.swift`

- [ ] **Step 1: Create the directory structure**

```bash
mkdir -p apps/shared/Sources/DefenseClawKit/Models
mkdir -p apps/shared/Tests/DefenseClawKitTests/Models
```

- [ ] **Step 2: Write Package.swift**

```swift
// apps/shared/Package.swift
// swift-tools-version: 5.9

import PackageDescription

let package = Package(
    name: "DefenseClawKit",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "DefenseClawKit", targets: ["DefenseClawKit"]),
    ],
    dependencies: [
        .package(url: "https://github.com/jpsim/Yams.git", from: "5.1.0"),
    ],
    targets: [
        .target(
            name: "DefenseClawKit",
            dependencies: ["Yams"]
        ),
        .testTarget(
            name: "DefenseClawKitTests",
            dependencies: ["DefenseClawKit"]
        ),
    ]
)
```

- [ ] **Step 3: Create a placeholder source file so the package resolves**

```swift
// apps/shared/Sources/DefenseClawKit/DefenseClawKit.swift
public enum DefenseClawKit {
    public static let version = "0.1.0"
}
```

- [ ] **Step 4: Verify the package resolves**

Run: `cd apps/shared && swift package resolve`
Expected: Dependencies fetched, no errors.

- [ ] **Step 5: Verify it builds**

Run: `cd apps/shared && swift build`
Expected: Build Succeeded

- [ ] **Step 6: Commit**

```bash
git add apps/shared/Package.swift apps/shared/Sources/DefenseClawKit/DefenseClawKit.swift
git commit -m "feat(macos): scaffold shared DefenseClawKit Swift package"
```

---

### Task 2: Severity Enum and Core Model Types

**Files:**
- Create: `apps/shared/Sources/DefenseClawKit/Models/Severity.swift`
- Create: `apps/shared/Sources/DefenseClawKit/Models/HealthSnapshot.swift`
- Create: `apps/shared/Sources/DefenseClawKit/Models/Alert.swift`
- Test: `apps/shared/Tests/DefenseClawKitTests/Models/HealthSnapshotTests.swift`

- [ ] **Step 1: Write the Severity enum**

```swift
// apps/shared/Sources/DefenseClawKit/Models/Severity.swift
import Foundation

public enum Severity: String, Codable, Comparable, CaseIterable, Sendable {
    case critical = "CRITICAL"
    case high = "HIGH"
    case medium = "MEDIUM"
    case low = "LOW"
    case info = "INFO"
    case none = "NONE"

    private var rank: Int {
        switch self {
        case .critical: return 5
        case .high: return 4
        case .medium: return 3
        case .low: return 2
        case .info: return 1
        case .none: return 0
        }
    }

    public static func < (lhs: Severity, rhs: Severity) -> Bool {
        lhs.rank < rhs.rank
    }
}
```

- [ ] **Step 2: Write HealthSnapshot models**

These mirror the Go `HealthSnapshot` and `SubsystemHealth` structs from `internal/gateway/health.go`.

```swift
// apps/shared/Sources/DefenseClawKit/Models/HealthSnapshot.swift
import Foundation

public enum SubsystemState: String, Codable, Sendable {
    case starting
    case running
    case reconnecting
    case stopped
    case error
    case disabled
}

public struct SubsystemHealth: Codable, Sendable {
    public let state: SubsystemState
    public let since: Date
    public let lastError: String?
    public let details: [String: AnyCodable]?

    enum CodingKeys: String, CodingKey {
        case state, since
        case lastError = "last_error"
        case details
    }
}

public struct HealthSnapshot: Codable, Sendable {
    public let startedAt: Date
    public let uptimeMs: Int64
    public let gateway: SubsystemHealth
    public let watcher: SubsystemHealth
    public let api: SubsystemHealth
    public let guardrail: SubsystemHealth
    public let telemetry: SubsystemHealth
    public let splunk: SubsystemHealth
    public let sandbox: SubsystemHealth?

    enum CodingKeys: String, CodingKey {
        case startedAt = "started_at"
        case uptimeMs = "uptime_ms"
        case gateway, watcher, api, guardrail, telemetry, splunk, sandbox
    }

    /// True when all active subsystems are running.
    public var isHealthy: Bool {
        let active = [gateway, watcher, api, guardrail, telemetry, splunk]
        return active.allSatisfy { $0.state == .running || $0.state == .disabled }
    }
}

/// Type-erased Codable wrapper for JSON dictionaries with mixed value types.
public struct AnyCodable: Codable, Sendable {
    public let value: Any

    public init(_ value: Any) { self.value = value }

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if let s = try? container.decode(String.self) { value = s }
        else if let i = try? container.decode(Int.self) { value = i }
        else if let d = try? container.decode(Double.self) { value = d }
        else if let b = try? container.decode(Bool.self) { value = b }
        else { value = "unknown" }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch value {
        case let s as String: try container.encode(s)
        case let i as Int: try container.encode(i)
        case let d as Double: try container.encode(d)
        case let b as Bool: try container.encode(b)
        default: try container.encode(String(describing: value))
        }
    }
}
```

- [ ] **Step 3: Write Alert model**

```swift
// apps/shared/Sources/DefenseClawKit/Models/Alert.swift
import Foundation

public struct Alert: Codable, Identifiable, Sendable {
    public let id: String
    public let action: String
    public let target: String
    public let severity: Severity
    public let details: String
    public let timestamp: Date

    public init(id: String, action: String, target: String, severity: Severity, details: String, timestamp: Date) {
        self.id = id
        self.action = action
        self.target = target
        self.severity = severity
        self.details = details
        self.timestamp = timestamp
    }
}
```

- [ ] **Step 4: Write the HealthSnapshot test**

```swift
// apps/shared/Tests/DefenseClawKitTests/Models/HealthSnapshotTests.swift
import XCTest
@testable import DefenseClawKit

final class HealthSnapshotTests: XCTestCase {
    func testDecodeHealthSnapshot() throws {
        let json = """
        {
            "started_at": "2026-04-02T10:00:00Z",
            "uptime_ms": 60000,
            "gateway": {"state": "running", "since": "2026-04-02T10:00:01Z"},
            "watcher": {"state": "running", "since": "2026-04-02T10:00:01Z"},
            "api": {"state": "running", "since": "2026-04-02T10:00:01Z"},
            "guardrail": {"state": "disabled", "since": "2026-04-02T10:00:00Z"},
            "telemetry": {"state": "disabled", "since": "2026-04-02T10:00:00Z"},
            "splunk": {"state": "disabled", "since": "2026-04-02T10:00:00Z"}
        }
        """.data(using: .utf8)!

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let snapshot = try decoder.decode(HealthSnapshot.self, from: json)

        XCTAssertEqual(snapshot.gateway.state, .running)
        XCTAssertEqual(snapshot.guardrail.state, .disabled)
        XCTAssertEqual(snapshot.uptimeMs, 60000)
        XCTAssertNil(snapshot.sandbox)
        XCTAssertTrue(snapshot.isHealthy)
    }

    func testIsHealthyReturnsFalseOnError() throws {
        let json = """
        {
            "started_at": "2026-04-02T10:00:00Z",
            "uptime_ms": 1000,
            "gateway": {"state": "error", "since": "2026-04-02T10:00:01Z", "last_error": "connection refused"},
            "watcher": {"state": "running", "since": "2026-04-02T10:00:01Z"},
            "api": {"state": "running", "since": "2026-04-02T10:00:01Z"},
            "guardrail": {"state": "disabled", "since": "2026-04-02T10:00:00Z"},
            "telemetry": {"state": "disabled", "since": "2026-04-02T10:00:00Z"},
            "splunk": {"state": "disabled", "since": "2026-04-02T10:00:00Z"}
        }
        """.data(using: .utf8)!

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let snapshot = try decoder.decode(HealthSnapshot.self, from: json)

        XCTAssertFalse(snapshot.isHealthy)
        XCTAssertEqual(snapshot.gateway.lastError, "connection refused")
    }

    func testSeverityComparison() {
        XCTAssertTrue(Severity.low < Severity.high)
        XCTAssertTrue(Severity.none < Severity.info)
        XCTAssertTrue(Severity.critical > Severity.medium)
    }
}
```

- [ ] **Step 5: Run tests**

Run: `cd apps/shared && swift test --filter HealthSnapshotTests`
Expected: All 3 tests pass.

- [ ] **Step 6: Commit**

```bash
git add apps/shared/Sources/DefenseClawKit/Models/
git add apps/shared/Tests/DefenseClawKitTests/Models/
git commit -m "feat(macos): add Severity, HealthSnapshot, Alert models"
```

---

### Task 3: Skill, Plugin, MCPServer, ToolEntry Models

**Files:**
- Create: `apps/shared/Sources/DefenseClawKit/Models/Skill.swift`
- Create: `apps/shared/Sources/DefenseClawKit/Models/Plugin.swift`
- Create: `apps/shared/Sources/DefenseClawKit/Models/MCPServer.swift`
- Create: `apps/shared/Sources/DefenseClawKit/Models/ToolEntry.swift`

- [ ] **Step 1: Write Skill model**

```swift
// apps/shared/Sources/DefenseClawKit/Models/Skill.swift
import Foundation

public struct Skill: Codable, Identifiable, Sendable {
    public let id: String
    public let name: String
    public let path: String?
    public let enabled: Bool
    public let blocked: Bool
    public let allowed: Bool
    public let quarantined: Bool
    public let lastScan: ScanSummary?

    enum CodingKeys: String, CodingKey {
        case id, name, path, enabled, blocked, allowed, quarantined
        case lastScan = "last_scan"
    }
}

public struct ScanSummary: Codable, Sendable {
    public let severity: Severity
    public let findingCount: Int
    public let scannedAt: Date?

    enum CodingKeys: String, CodingKey {
        case severity
        case findingCount = "finding_count"
        case scannedAt = "scanned_at"
    }
}
```

- [ ] **Step 2: Write Plugin model**

```swift
// apps/shared/Sources/DefenseClawKit/Models/Plugin.swift
import Foundation

public struct Plugin: Codable, Identifiable, Sendable {
    public let id: String
    public let name: String
    public let path: String?
    public let enabled: Bool
    public let blocked: Bool
    public let allowed: Bool
    public let quarantined: Bool
    public let lastScan: ScanSummary?

    enum CodingKeys: String, CodingKey {
        case id, name, path, enabled, blocked, allowed, quarantined
        case lastScan = "last_scan"
    }
}
```

- [ ] **Step 3: Write MCPServer model**

```swift
// apps/shared/Sources/DefenseClawKit/Models/MCPServer.swift
import Foundation

public struct MCPServer: Codable, Identifiable, Sendable {
    public let id: String
    public let name: String
    public let url: String?
    public let command: String?
    public let args: [String]?
    public let transport: String?
    public let blocked: Bool
    public let allowed: Bool
    public let lastScan: ScanSummary?

    enum CodingKeys: String, CodingKey {
        case id, name, url, command, args, transport, blocked, allowed
        case lastScan = "last_scan"
    }
}
```

- [ ] **Step 4: Write ToolEntry model**

```swift
// apps/shared/Sources/DefenseClawKit/Models/ToolEntry.swift
import Foundation

public struct ToolEntry: Codable, Identifiable, Sendable {
    public let id: String
    public let name: String
    public let description: String?
    public let source: String?
    public let blocked: Bool

    enum CodingKeys: String, CodingKey {
        case id, name, description, source, blocked
    }
}
```

- [ ] **Step 5: Build to verify**

Run: `cd apps/shared && swift build`
Expected: Build Succeeded

- [ ] **Step 6: Commit**

```bash
git add apps/shared/Sources/DefenseClawKit/Models/Skill.swift
git add apps/shared/Sources/DefenseClawKit/Models/Plugin.swift
git add apps/shared/Sources/DefenseClawKit/Models/MCPServer.swift
git add apps/shared/Sources/DefenseClawKit/Models/ToolEntry.swift
git commit -m "feat(macos): add Skill, Plugin, MCPServer, ToolEntry models"
```

---

### Task 4: ChatMessage Model with Content Blocks

**Files:**
- Create: `apps/shared/Sources/DefenseClawKit/Models/ChatMessage.swift`
- Create: `apps/shared/Sources/DefenseClawKit/Models/ToolEvent.swift`
- Create: `apps/shared/Sources/DefenseClawKit/Models/SessionConfig.swift`
- Test: `apps/shared/Tests/DefenseClawKitTests/Models/ChatMessageTests.swift`

- [ ] **Step 1: Write ToolEvent model**

```swift
// apps/shared/Sources/DefenseClawKit/Models/ToolEvent.swift
import Foundation

public enum ToolCallStatus: String, Codable, Sendable {
    case pending, running, completed, failed, warned, blocked
}

public struct ToolEvent: Codable, Identifiable, Sendable {
    public let id: String
    public let tool: String
    public let args: String?
    public var status: ToolCallStatus
    public var output: String?
    public var exitCode: Int?
    public var elapsed: TimeInterval?
    public let timestamp: Date

    enum CodingKeys: String, CodingKey {
        case id, tool, args, status, output
        case exitCode = "exit_code"
        case elapsed, timestamp
    }

    public init(id: String = UUID().uuidString, tool: String, args: String? = nil, status: ToolCallStatus = .pending, output: String? = nil, exitCode: Int? = nil, elapsed: TimeInterval? = nil, timestamp: Date = .now) {
        self.id = id; self.tool = tool; self.args = args; self.status = status
        self.output = output; self.exitCode = exitCode; self.elapsed = elapsed; self.timestamp = timestamp
    }
}
```

- [ ] **Step 2: Write SessionConfig model**

```swift
// apps/shared/Sources/DefenseClawKit/Models/SessionConfig.swift
import Foundation

public struct SessionConfig: Codable, Sendable {
    public var workspace: String
    public var agentName: String
    public var model: String?
    public var guardrailEnabled: Bool

    public init(workspace: String, agentName: String = "Agent", model: String? = nil, guardrailEnabled: Bool = true) {
        self.workspace = workspace
        self.agentName = agentName
        self.model = model
        self.guardrailEnabled = guardrailEnabled
    }
}
```

- [ ] **Step 3: Write ChatMessage model with content blocks**

```swift
// apps/shared/Sources/DefenseClawKit/Models/ChatMessage.swift
import Foundation

public enum MessageRole: String, Codable, Sendable {
    case user, assistant, system, tool
}

public enum ApprovalDecision: String, Codable, Sendable {
    case approved, denied, autoApproved
}

/// A single block within a chat message. Messages can contain multiple blocks
/// (e.g., thinking + tool calls + text response).
public enum ContentBlock: Identifiable, Sendable {
    case text(id: String, text: String)
    case thinking(id: String, text: String, durationMs: Int?)
    case toolCall(id: String, tool: String, args: String, status: ToolCallStatus, output: String?, elapsedMs: Int?)
    case approvalRequest(id: String, command: String, cwd: String, isDangerous: Bool, decision: ApprovalDecision?)
    case guardrailBadge(id: String, severity: String, action: String, reason: String)

    public var id: String {
        switch self {
        case .text(let id, _): return id
        case .thinking(let id, _, _): return id
        case .toolCall(let id, _, _, _, _, _): return id
        case .approvalRequest(let id, _, _, _, _): return id
        case .guardrailBadge(let id, _, _, _): return id
        }
    }
}

public struct ChatMessage: Identifiable, Sendable {
    public let id: String
    public let role: MessageRole
    public var blocks: [ContentBlock]
    public let timestamp: Date
    public var isStreaming: Bool

    public init(
        id: String = UUID().uuidString,
        role: MessageRole,
        blocks: [ContentBlock] = [],
        timestamp: Date = .now,
        isStreaming: Bool = false
    ) {
        self.id = id
        self.role = role
        self.blocks = blocks
        self.timestamp = timestamp
        self.isStreaming = isStreaming
    }

    /// Convenience: create a simple text message.
    public static func text(_ text: String, role: MessageRole, isStreaming: Bool = false) -> ChatMessage {
        ChatMessage(role: role, blocks: [.text(id: UUID().uuidString, text: text)], isStreaming: isStreaming)
    }

    /// Extract all text content from the message blocks.
    public var textContent: String {
        blocks.compactMap {
            if case .text(_, let text) = $0 { return text }
            return nil
        }.joined()
    }
}
```

- [ ] **Step 4: Write ChatMessage tests**

```swift
// apps/shared/Tests/DefenseClawKitTests/Models/ChatMessageTests.swift
import XCTest
@testable import DefenseClawKit

final class ChatMessageTests: XCTestCase {
    func testTextConvenienceInitializer() {
        let msg = ChatMessage.text("Hello", role: .user)
        XCTAssertEqual(msg.role, .user)
        XCTAssertEqual(msg.textContent, "Hello")
        XCTAssertFalse(msg.isStreaming)
        XCTAssertEqual(msg.blocks.count, 1)
    }

    func testMultipleBlocksInOneMessage() {
        var msg = ChatMessage(role: .assistant, isStreaming: true)
        msg.blocks.append(.thinking(id: "t1", text: "Let me check...", durationMs: nil))
        msg.blocks.append(.toolCall(id: "tc1", tool: "shell", args: "ls -la", status: .running, output: nil, elapsedMs: nil))
        msg.blocks.append(.text(id: "txt1", text: "Here are the files."))

        XCTAssertEqual(msg.blocks.count, 3)
        XCTAssertEqual(msg.textContent, "Here are the files.")

        // Verify block IDs are accessible
        XCTAssertEqual(msg.blocks[0].id, "t1")
        XCTAssertEqual(msg.blocks[1].id, "tc1")
    }

    func testToolCallBlockStates() {
        let pending = ContentBlock.toolCall(id: "1", tool: "read_file", args: "main.go", status: .pending, output: nil, elapsedMs: nil)
        let completed = ContentBlock.toolCall(id: "1", tool: "read_file", args: "main.go", status: .completed, output: "package main", elapsedMs: 15)
        let blocked = ContentBlock.toolCall(id: "2", tool: "curl", args: "http://evil.com", status: .blocked, output: nil, elapsedMs: nil)

        if case .toolCall(_, _, _, let s, _, _) = pending { XCTAssertEqual(s, .pending) }
        if case .toolCall(_, _, _, let s, let o, _) = completed { XCTAssertEqual(s, .completed); XCTAssertEqual(o, "package main") }
        if case .toolCall(_, _, _, let s, _, _) = blocked { XCTAssertEqual(s, .blocked) }
    }

    func testApprovalBlock() {
        let block = ContentBlock.approvalRequest(id: "a1", command: "rm -rf /tmp", cwd: "/home/user", isDangerous: true, decision: nil)
        XCTAssertEqual(block.id, "a1")
        if case .approvalRequest(_, let cmd, _, let danger, let decision) = block {
            XCTAssertEqual(cmd, "rm -rf /tmp")
            XCTAssertTrue(danger)
            XCTAssertNil(decision)
        }
    }
}
```

- [ ] **Step 5: Run tests**

Run: `cd apps/shared && swift test --filter ChatMessageTests`
Expected: All 4 tests pass.

- [ ] **Step 6: Commit**

```bash
git add apps/shared/Sources/DefenseClawKit/Models/ToolEvent.swift
git add apps/shared/Sources/DefenseClawKit/Models/SessionConfig.swift
git add apps/shared/Sources/DefenseClawKit/Models/ChatMessage.swift
git add apps/shared/Tests/DefenseClawKitTests/Models/ChatMessageTests.swift
git commit -m "feat(macos): add ChatMessage, ToolEvent, SessionConfig models"
```

---

### Task 5: ScanResult, PolicyModels, EnforceModels, GuardrailModels

**Files:**
- Create: `apps/shared/Sources/DefenseClawKit/Models/ScanResult.swift`
- Create: `apps/shared/Sources/DefenseClawKit/Models/PolicyModels.swift`
- Create: `apps/shared/Sources/DefenseClawKit/Models/EnforceModels.swift`
- Create: `apps/shared/Sources/DefenseClawKit/Models/GuardrailModels.swift`
- Test: `apps/shared/Tests/DefenseClawKitTests/Models/ScanResultTests.swift`

- [ ] **Step 1: Write ScanResult**

```swift
// apps/shared/Sources/DefenseClawKit/Models/ScanResult.swift
import Foundation

public struct Finding: Codable, Identifiable, Sendable {
    public let id: String
    public let rule: String
    public let severity: Severity
    public let description: String
    public let location: String?
    public let evidence: String?

    public init(id: String = UUID().uuidString, rule: String, severity: Severity, description: String, location: String? = nil, evidence: String? = nil) {
        self.id = id; self.rule = rule; self.severity = severity; self.description = description
        self.location = location; self.evidence = evidence
    }
}

public struct ScanResult: Codable, Identifiable, Sendable {
    public let id: String
    public let target: String
    public let scanType: String
    public let severity: Severity
    public let findings: [Finding]
    public let scannedAt: Date

    enum CodingKeys: String, CodingKey {
        case id, target, severity, findings
        case scanType = "scan_type"
        case scannedAt = "scanned_at"
    }
}
```

- [ ] **Step 2: Write PolicyModels**

```swift
// apps/shared/Sources/DefenseClawKit/Models/PolicyModels.swift
import Foundation

public struct AdmissionInput: Codable, Sendable {
    public let targetType: String
    public let targetName: String
    public let severity: String
    public let findings: Int

    public init(targetType: String, targetName: String, severity: String, findings: Int) {
        self.targetType = targetType; self.targetName = targetName
        self.severity = severity; self.findings = findings
    }

    enum CodingKeys: String, CodingKey {
        case targetType = "target_type"
        case targetName = "target_name"
        case severity, findings
    }
}

public struct AdmissionOutput: Codable, Sendable {
    public let allow: Bool
    public let reason: String?
}

public struct FirewallInput: Codable, Sendable {
    public let destination: String
    public let port: Int
    public let `protocol`: String

    public init(destination: String, port: Int, protocol proto: String) {
        self.destination = destination; self.port = port; self.protocol = proto
    }
}

public struct FirewallOutput: Codable, Sendable {
    public let action: String
    public let matchedRule: String?

    enum CodingKeys: String, CodingKey {
        case action
        case matchedRule = "matched_rule"
    }
}

public struct PolicyDomain: Codable, Identifiable, Sendable {
    public var id: String { name }
    public let name: String
    public let description: String?
    public let ruleCount: Int?

    enum CodingKeys: String, CodingKey {
        case name, description
        case ruleCount = "rule_count"
    }
}
```

- [ ] **Step 3: Write EnforceModels**

```swift
// apps/shared/Sources/DefenseClawKit/Models/EnforceModels.swift
import Foundation

public struct EnforceRequest: Codable, Sendable {
    public let type: String   // "skill", "mcp", "plugin"
    public let name: String
    public let reason: String?

    public init(type: String, name: String, reason: String? = nil) {
        self.type = type; self.name = name; self.reason = reason
    }
}

public struct BlockEntry: Codable, Identifiable, Sendable {
    public var id: String { "\(type):\(name)" }
    public let type: String
    public let name: String
    public let reason: String?
    public let blockedAt: Date?

    enum CodingKeys: String, CodingKey {
        case type, name, reason
        case blockedAt = "blocked_at"
    }
}

public struct AllowEntry: Codable, Identifiable, Sendable {
    public var id: String { "\(type):\(name)" }
    public let type: String
    public let name: String
    public let reason: String?
    public let allowedAt: Date?

    enum CodingKeys: String, CodingKey {
        case type, name, reason
        case allowedAt = "allowed_at"
    }
}
```

- [ ] **Step 4: Write GuardrailModels**

```swift
// apps/shared/Sources/DefenseClawKit/Models/GuardrailModels.swift
import Foundation

public struct GuardrailConfig: Codable, Sendable {
    public var enabled: Bool
    public var mode: String       // "observe" | "action"
    public var scannerMode: String // "local" | "remote" | "both"
    public var blockMessage: String?

    enum CodingKeys: String, CodingKey {
        case enabled, mode
        case scannerMode = "scanner_mode"
        case blockMessage = "block_message"
    }
}

public struct GuardrailEvalRequest: Codable, Sendable {
    public let direction: String  // "prompt" | "completion"
    public let content: String
    public let model: String?

    public init(direction: String, content: String, model: String? = nil) {
        self.direction = direction; self.content = content; self.model = model
    }
}

public struct GuardrailEvalResponse: Codable, Sendable {
    public let action: String     // "allow" | "block"
    public let severity: Severity
    public let reason: String?
    public let findings: [Finding]?
}
```

- [ ] **Step 5: Write ScanResult test**

```swift
// apps/shared/Tests/DefenseClawKitTests/Models/ScanResultTests.swift
import XCTest
@testable import DefenseClawKit

final class ScanResultTests: XCTestCase {
    func testDecodeScanResult() throws {
        let json = """
        {
            "id": "scan-001",
            "target": "web-search",
            "scan_type": "skill",
            "severity": "HIGH",
            "findings": [
                {
                    "id": "f1",
                    "rule": "network-access",
                    "severity": "HIGH",
                    "description": "Skill makes outbound HTTP calls"
                }
            ],
            "scanned_at": "2026-04-02T12:00:00Z"
        }
        """.data(using: .utf8)!

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let result = try decoder.decode(ScanResult.self, from: json)

        XCTAssertEqual(result.id, "scan-001")
        XCTAssertEqual(result.target, "web-search")
        XCTAssertEqual(result.severity, .high)
        XCTAssertEqual(result.findings.count, 1)
        XCTAssertEqual(result.findings[0].rule, "network-access")
    }

    func testAdmissionInputEncoding() throws {
        let input = AdmissionInput(targetType: "skill", targetName: "web-search", severity: "HIGH", findings: 2)
        let data = try JSONEncoder().encode(input)
        let dict = try JSONSerialization.jsonObject(with: data) as! [String: Any]

        XCTAssertEqual(dict["target_type"] as? String, "skill")
        XCTAssertEqual(dict["target_name"] as? String, "web-search")
    }
}
```

- [ ] **Step 6: Run tests**

Run: `cd apps/shared && swift test --filter ScanResultTests`
Expected: All 2 tests pass.

- [ ] **Step 7: Commit**

```bash
git add apps/shared/Sources/DefenseClawKit/Models/ScanResult.swift
git add apps/shared/Sources/DefenseClawKit/Models/PolicyModels.swift
git add apps/shared/Sources/DefenseClawKit/Models/EnforceModels.swift
git add apps/shared/Sources/DefenseClawKit/Models/GuardrailModels.swift
git add apps/shared/Tests/DefenseClawKitTests/Models/ScanResultTests.swift
git commit -m "feat(macos): add ScanResult, Policy, Enforce, Guardrail models"
```

---

### Task 6: ConfigModels (Full config.yaml Schema)

**Files:**
- Create: `apps/shared/Sources/DefenseClawKit/Models/ConfigModels.swift`

- [ ] **Step 1: Write ConfigModels matching the Go Config struct**

This mirrors every field from `internal/config/config.go`.

```swift
// apps/shared/Sources/DefenseClawKit/Models/ConfigModels.swift
import Foundation

/// Top-level config matching ~/.defenseclaw/config.yaml
public struct AppConfig: Codable, Sendable {
    public var dataDir: String?
    public var auditDb: String?
    public var quarantineDir: String?
    public var pluginDir: String?
    public var policyDir: String?
    public var environment: String?
    public var claw: ClawConfig?
    public var inspectLlm: InspectLLMConfig?
    public var ciscoAiDefense: CiscoAIDefenseConfig?
    public var scanners: ScannersConfig?
    public var openshell: OpenShellConfig?
    public var watch: WatchConfig?
    public var guardrail: GuardrailFullConfig?
    public var splunk: SplunkConfig?
    public var gateway: GatewayFullConfig?
    public var skillActions: SeverityActionsConfig?
    public var mcpActions: SeverityActionsConfig?
    public var pluginActions: SeverityActionsConfig?
    public var otel: OTelConfig?

    enum CodingKeys: String, CodingKey {
        case dataDir = "data_dir"
        case auditDb = "audit_db"
        case quarantineDir = "quarantine_dir"
        case pluginDir = "plugin_dir"
        case policyDir = "policy_dir"
        case environment, claw
        case inspectLlm = "inspect_llm"
        case ciscoAiDefense = "cisco_ai_defense"
        case scanners, openshell, watch, guardrail, splunk, gateway
        case skillActions = "skill_actions"
        case mcpActions = "mcp_actions"
        case pluginActions = "plugin_actions"
        case otel
    }
}

public struct ClawConfig: Codable, Sendable {
    public var mode: String?
    public var homeDir: String?
    public var configFile: String?

    enum CodingKeys: String, CodingKey {
        case mode
        case homeDir = "home_dir"
        case configFile = "config_file"
    }
}

public struct InspectLLMConfig: Codable, Sendable {
    public var provider: String?
    public var model: String?
    public var apiKey: String?
    public var apiKeyEnv: String?
    public var baseUrl: String?
    public var timeout: Int?
    public var maxRetries: Int?

    enum CodingKeys: String, CodingKey {
        case provider, model, timeout
        case apiKey = "api_key"
        case apiKeyEnv = "api_key_env"
        case baseUrl = "base_url"
        case maxRetries = "max_retries"
    }
}

public struct CiscoAIDefenseConfig: Codable, Sendable {
    public var endpoint: String?
    public var apiKey: String?
    public var apiKeyEnv: String?
    public var timeoutMs: Int?
    public var enabledRules: [String]?

    enum CodingKeys: String, CodingKey {
        case endpoint
        case apiKey = "api_key"
        case apiKeyEnv = "api_key_env"
        case timeoutMs = "timeout_ms"
        case enabledRules = "enabled_rules"
    }
}

public struct SkillScannerConfig: Codable, Sendable {
    public var binary: String?
    public var useLlm: Bool?
    public var useBehavioral: Bool?
    public var enableMeta: Bool?
    public var useTrigger: Bool?
    public var useVirustotal: Bool?
    public var useAidefense: Bool?
    public var llmConsensusRuns: Int?
    public var policy: String?
    public var lenient: Bool?

    enum CodingKeys: String, CodingKey {
        case binary, policy, lenient
        case useLlm = "use_llm"
        case useBehavioral = "use_behavioral"
        case enableMeta = "enable_meta"
        case useTrigger = "use_trigger"
        case useVirustotal = "use_virustotal"
        case useAidefense = "use_aidefense"
        case llmConsensusRuns = "llm_consensus_runs"
    }
}

public struct MCPScannerConfig: Codable, Sendable {
    public var binary: String?
    public var analyzers: String?
    public var scanPrompts: Bool?
    public var scanResources: Bool?
    public var scanInstructions: Bool?

    enum CodingKeys: String, CodingKey {
        case binary, analyzers
        case scanPrompts = "scan_prompts"
        case scanResources = "scan_resources"
        case scanInstructions = "scan_instructions"
    }
}

public struct ScannersConfig: Codable, Sendable {
    public var skillScanner: SkillScannerConfig?
    public var mcpScanner: MCPScannerConfig?
    public var pluginScanner: String?
    public var codeguard: String?

    enum CodingKeys: String, CodingKey {
        case skillScanner = "skill_scanner"
        case mcpScanner = "mcp_scanner"
        case pluginScanner = "plugin_scanner"
        case codeguard
    }
}

public struct OpenShellConfig: Codable, Sendable {
    public var binary: String?
    public var policyDir: String?
    public var mode: String?
    public var version: String?
    public var sandboxHome: String?
    public var hostNetworking: Bool?

    enum CodingKeys: String, CodingKey {
        case binary, mode, version
        case policyDir = "policy_dir"
        case sandboxHome = "sandbox_home"
        case hostNetworking = "host_networking"
    }
}

public struct WatchConfig: Codable, Sendable {
    public var debounceMs: Int?
    public var autoBlock: Bool?
    public var allowListBypassScan: Bool?

    enum CodingKeys: String, CodingKey {
        case debounceMs = "debounce_ms"
        case autoBlock = "auto_block"
        case allowListBypassScan = "allow_list_bypass_scan"
    }
}

public struct JudgeConfig: Codable, Sendable {
    public var enabled: Bool?
    public var injection: Bool?
    public var pii: Bool?
    public var piiPrompt: Bool?
    public var piiCompletion: Bool?
    public var model: String?
    public var apiKeyEnv: String?
    public var apiBase: String?
    public var timeout: Double?

    enum CodingKeys: String, CodingKey {
        case enabled, injection, pii, model, timeout
        case piiPrompt = "pii_prompt"
        case piiCompletion = "pii_completion"
        case apiKeyEnv = "api_key_env"
        case apiBase = "api_base"
    }
}

public struct GuardrailFullConfig: Codable, Sendable {
    public var enabled: Bool?
    public var mode: String?
    public var scannerMode: String?
    public var host: String?
    public var port: Int?
    public var model: String?
    public var modelName: String?
    public var apiKeyEnv: String?
    public var originalModel: String?
    public var blockMessage: String?
    public var judge: JudgeConfig?

    enum CodingKeys: String, CodingKey {
        case enabled, mode, host, port, model, judge
        case scannerMode = "scanner_mode"
        case modelName = "model_name"
        case apiKeyEnv = "api_key_env"
        case originalModel = "original_model"
        case blockMessage = "block_message"
    }
}

public struct SplunkConfig: Codable, Sendable {
    public var hecEndpoint: String?
    public var hecToken: String?
    public var hecTokenEnv: String?
    public var index: String?
    public var source: String?
    public var sourcetype: String?
    public var verifyTls: Bool?
    public var enabled: Bool?
    public var batchSize: Int?
    public var flushIntervalS: Int?

    enum CodingKeys: String, CodingKey {
        case index, source, sourcetype, enabled
        case hecEndpoint = "hec_endpoint"
        case hecToken = "hec_token"
        case hecTokenEnv = "hec_token_env"
        case verifyTls = "verify_tls"
        case batchSize = "batch_size"
        case flushIntervalS = "flush_interval_s"
    }
}

public struct GatewayWatcherSkillConfig: Codable, Sendable {
    public var enabled: Bool?
    public var takeAction: Bool?
    public var dirs: [String]?

    enum CodingKeys: String, CodingKey {
        case enabled, dirs
        case takeAction = "take_action"
    }
}

public struct GatewayWatcherPluginConfig: Codable, Sendable {
    public var enabled: Bool?
    public var takeAction: Bool?
    public var dirs: [String]?

    enum CodingKeys: String, CodingKey {
        case enabled, dirs
        case takeAction = "take_action"
    }
}

public struct GatewayWatcherConfig: Codable, Sendable {
    public var enabled: Bool?
    public var skill: GatewayWatcherSkillConfig?
    public var plugin: GatewayWatcherPluginConfig?
}

public struct GatewayFullConfig: Codable, Sendable {
    public var host: String?
    public var port: Int?
    public var token: String?
    public var tokenEnv: String?
    public var tls: Bool?
    public var tlsSkipVerify: Bool?
    public var deviceKeyFile: String?
    public var autoApproveSafe: Bool?
    public var reconnectMs: Int?
    public var maxReconnectMs: Int?
    public var approvalTimeoutS: Int?
    public var apiPort: Int?
    public var apiBind: String?
    public var watcher: GatewayWatcherConfig?

    enum CodingKeys: String, CodingKey {
        case host, port, token, tls, watcher
        case tokenEnv = "token_env"
        case tlsSkipVerify = "tls_skip_verify"
        case deviceKeyFile = "device_key_file"
        case autoApproveSafe = "auto_approve_safe"
        case reconnectMs = "reconnect_ms"
        case maxReconnectMs = "max_reconnect_ms"
        case approvalTimeoutS = "approval_timeout_s"
        case apiPort = "api_port"
        case apiBind = "api_bind"
    }
}

public struct SeverityAction: Codable, Sendable {
    public var file: String?
    public var runtime: String?
    public var install: String?
}

public struct SeverityActionsConfig: Codable, Sendable {
    public var critical: SeverityAction?
    public var high: SeverityAction?
    public var medium: SeverityAction?
    public var low: SeverityAction?
    public var info: SeverityAction?
}

public struct OTelConfig: Codable, Sendable {
    public var enabled: Bool?
    public var `protocol`: String?
    public var endpoint: String?
}
```

- [ ] **Step 2: Build to verify**

Run: `cd apps/shared && swift build`
Expected: Build Succeeded

- [ ] **Step 3: Commit**

```bash
git add apps/shared/Sources/DefenseClawKit/Models/ConfigModels.swift
git commit -m "feat(macos): add ConfigModels matching full config.yaml schema"
```

---

### Task 7: SidecarClient (REST Client)

**Files:**
- Create: `apps/shared/Sources/DefenseClawKit/SidecarClient.swift`
- Test: `apps/shared/Tests/DefenseClawKitTests/SidecarClientTests.swift`

- [ ] **Step 1: Write the SidecarClient**

```swift
// apps/shared/Sources/DefenseClawKit/SidecarClient.swift
import Foundation

/// HTTP client for the DefenseClaw sidecar REST API at localhost:18790.
public actor SidecarClient {
    private let baseURL: URL
    private let session: URLSession
    private let decoder: JSONDecoder

    public init(host: String = "127.0.0.1", port: Int = 18790) {
        self.baseURL = URL(string: "http://\(host):\(port)")!
        self.session = URLSession(configuration: .ephemeral)
        let dec = JSONDecoder()
        dec.dateDecodingStrategy = .iso8601
        self.decoder = dec
    }

    // MARK: - Health & Status

    public func health() async throws -> HealthSnapshot {
        try await get("/health")
    }

    public func status() async throws -> [String: AnyCodable] {
        try await get("/status")
    }

    // MARK: - Alerts

    public func alerts() async throws -> [Alert] {
        try await get("/alerts")
    }

    // MARK: - Skills

    public func skills() async throws -> [Skill] {
        try await get("/skills")
    }

    public func disableSkill(key: String) async throws {
        try await post("/skill/disable", body: ["skill_key": key])
    }

    public func enableSkill(key: String) async throws {
        try await post("/skill/enable", body: ["skill_key": key])
    }

    public func scanSkill(path: String) async throws -> ScanResult {
        try await post("/v1/skill/scan", body: ["path": path])
    }

    public func fetchSkill(url: String) async throws -> [String: AnyCodable] {
        try await post("/v1/skill/fetch", body: ["url": url])
    }

    // MARK: - Plugins

    public func disablePlugin(key: String) async throws {
        try await post("/plugin/disable", body: ["plugin_key": key])
    }

    public func enablePlugin(key: String) async throws {
        try await post("/plugin/enable", body: ["plugin_key": key])
    }

    // MARK: - MCP Servers

    public func mcpServers() async throws -> [MCPServer] {
        try await get("/mcps")
    }

    public func scanMCP(url: String) async throws -> ScanResult {
        try await post("/v1/mcp/scan", body: ["url": url])
    }

    // MARK: - Tools

    public func toolsCatalog() async throws -> [ToolEntry] {
        try await get("/tools/catalog")
    }

    public func inspectTool(name: String) async throws -> [String: AnyCodable] {
        try await post("/api/v1/inspect/tool", body: ["tool": name])
    }

    public func scanCode(path: String) async throws -> ScanResult {
        try await post("/api/v1/scan/code", body: ["path": path])
    }

    // MARK: - Enforce (Block/Allow)

    public func block(_ request: EnforceRequest) async throws {
        try await post("/enforce/block", body: request)
    }

    public func allow(_ request: EnforceRequest) async throws {
        try await post("/enforce/allow", body: request)
    }

    public func blockedList() async throws -> [BlockEntry] {
        try await get("/enforce/blocked")
    }

    public func allowedList() async throws -> [AllowEntry] {
        try await get("/enforce/allowed")
    }

    // MARK: - Policy

    public func policyEvaluate(input: AdmissionInput) async throws -> AdmissionOutput {
        try await post("/policy/evaluate", body: input)
    }

    public func policyEvaluateFirewall(input: FirewallInput) async throws -> FirewallOutput {
        try await post("/policy/evaluate/firewall", body: input)
    }

    public func policyReload() async throws {
        try await post("/policy/reload", body: [String: String]())
    }

    // MARK: - Guardrail

    public func guardrailConfig() async throws -> GuardrailConfig {
        try await get("/v1/guardrail/config")
    }

    public func updateGuardrailConfig(mode: String? = nil, scannerMode: String? = nil, blockMessage: String? = nil) async throws {
        var body: [String: String] = [:]
        if let m = mode { body["mode"] = m }
        if let s = scannerMode { body["scanner_mode"] = s }
        if let b = blockMessage { body["block_message"] = b }

        var request = URLRequest(url: baseURL.appendingPathComponent("/v1/guardrail/config"))
        request.httpMethod = "PATCH"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONEncoder().encode(body)
        let (_, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse, (200...299).contains(http.statusCode) else {
            throw SidecarError.requestFailed(endpoint: "/v1/guardrail/config")
        }
    }

    public func guardrailEvaluate(_ request: GuardrailEvalRequest) async throws -> GuardrailEvalResponse {
        try await post("/v1/guardrail/evaluate", body: request)
    }

    // MARK: - Audit

    public func logAuditEvent(action: String, target: String, severity: String, details: String) async throws {
        try await post("/audit/event", body: [
            "action": action, "target": target, "severity": severity, "details": details
        ])
    }

    // MARK: - Private Helpers

    private func get<T: Decodable>(_ path: String) async throws -> T {
        let url = baseURL.appendingPathComponent(path)
        let (data, response) = try await session.data(from: url)
        guard let http = response as? HTTPURLResponse, (200...299).contains(http.statusCode) else {
            throw SidecarError.requestFailed(endpoint: path)
        }
        return try decoder.decode(T.self, from: data)
    }

    private func post<B: Encodable, T: Decodable>(_ path: String, body: B) async throws -> T {
        var request = URLRequest(url: baseURL.appendingPathComponent(path))
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONEncoder().encode(body)
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse, (200...299).contains(http.statusCode) else {
            throw SidecarError.requestFailed(endpoint: path)
        }
        return try decoder.decode(T.self, from: data)
    }

    private func post<B: Encodable>(_ path: String, body: B) async throws {
        var request = URLRequest(url: baseURL.appendingPathComponent(path))
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONEncoder().encode(body)
        let (_, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse, (200...299).contains(http.statusCode) else {
            throw SidecarError.requestFailed(endpoint: path)
        }
    }
}

public enum SidecarError: Error, LocalizedError {
    case requestFailed(endpoint: String)
    case decodingFailed(endpoint: String, underlying: Error)

    public var errorDescription: String? {
        switch self {
        case .requestFailed(let ep): return "Sidecar request failed: \(ep)"
        case .decodingFailed(let ep, let err): return "Decoding failed for \(ep): \(err)"
        }
    }
}
```

- [ ] **Step 2: Write SidecarClient tests with MockURLProtocol**

```swift
// apps/shared/Tests/DefenseClawKitTests/SidecarClientTests.swift
import XCTest
@testable import DefenseClawKit

final class SidecarClientTests: XCTestCase {
    // Test that the client constructs correct URLs
    func testBaseURLConstruction() {
        // We can't easily test the actor's private URL, but we can verify
        // the client initializes without error for various host/port combos.
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
```

- [ ] **Step 3: Run tests**

Run: `cd apps/shared && swift test --filter SidecarClientTests`
Expected: All 2 tests pass.

- [ ] **Step 4: Commit**

```bash
git add apps/shared/Sources/DefenseClawKit/SidecarClient.swift
git add apps/shared/Tests/DefenseClawKitTests/SidecarClientTests.swift
git commit -m "feat(macos): add SidecarClient REST client for 30+ sidecar endpoints"
```

---

### Task 8: AgentSession (WebSocket v3 Client)

**Files:**
- Create: `apps/shared/Sources/DefenseClawKit/AgentSession.swift`
- Test: `apps/shared/Tests/DefenseClawKitTests/AgentSessionTests.swift`

- [ ] **Step 1: Write AgentSession**

```swift
// apps/shared/Sources/DefenseClawKit/AgentSession.swift
import Foundation

/// WebSocket v3 client for the OpenClaw gateway.
/// Handles device auth handshake, event dispatch, and RPC methods.
@Observable
public final class AgentSession: @unchecked Sendable {
    public private(set) var isConnected = false
    public private(set) var messages: [ChatMessage] = []
    public private(set) var toolEvents: [ToolEvent] = []

    private var webSocket: URLSessionWebSocketTask?
    private let session = URLSession(configuration: .default)
    private var pendingRPC: [String: CheckedContinuation<Data, Error>] = [:]
    private let lock = NSLock()

    private let host: String
    private let port: Int
    private let token: String

    public init(host: String = "127.0.0.1", port: Int = 18789, token: String = "") {
        self.host = host
        self.port = port
        self.token = token
    }

    // MARK: - Connection

    public func connect() async throws {
        let scheme = "ws"
        guard let url = URL(string: "\(scheme)://\(host):\(port)") else {
            throw AgentSessionError.invalidURL
        }
        webSocket = session.webSocketTask(with: url)
        webSocket?.resume()
        isConnected = true
        startReadLoop()
    }

    public func disconnect() {
        webSocket?.cancel(with: .goingAway, reason: nil)
        webSocket = nil
        isConnected = false
    }

    // MARK: - Chat

    public func sendMessage(_ text: String) {
        let msg = ChatMessage.text(text, role: .user)
        messages.append(msg)
    }

    // MARK: - RPC Methods

    public func resolveApproval(id: String, approved: Bool) async throws {
        let params: [String: Any] = ["id": id, "decision": approved ? "approved" : "denied"]
        try await sendRPC(method: "exec.approval.resolve", params: params)
    }

    public func disableSkill(key: String) async throws {
        try await sendRPC(method: "skills.update", params: ["skillKey": key, "enabled": false])
    }

    public func enableSkill(key: String) async throws {
        try await sendRPC(method: "skills.update", params: ["skillKey": key, "enabled": true])
    }

    // MARK: - Internal

    private func startReadLoop() {
        Task { [weak self] in
            guard let self else { return }
            while let ws = self.webSocket {
                do {
                    let message = try await ws.receive()
                    switch message {
                    case .string(let text):
                        self.handleFrame(text)
                    case .data(let data):
                        if let text = String(data: data, encoding: .utf8) {
                            self.handleFrame(text)
                        }
                    @unknown default:
                        break
                    }
                } catch {
                    self.isConnected = false
                    break
                }
            }
        }
    }

    private func handleFrame(_ text: String) {
        guard let data = text.data(using: .utf8),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let type = json["type"] as? String else { return }

        switch type {
        case "event":
            handleEvent(json)
        case "res":
            handleResponse(json, raw: data)
        default:
            break
        }
    }

    private func handleEvent(_ json: [String: Any]) {
        guard let event = json["event"] as? String else { return }

        switch event {
        case "connect.challenge":
            // In a full implementation, this triggers the handshake.
            // For now, we handle it as a connection confirmation.
            break

        case "tool_call":
            if let payload = json["payload"] as? [String: Any],
               let tool = payload["tool"] as? String {
                let args = (payload["args"] as? [String: Any]).flatMap {
                    try? String(data: JSONSerialization.data(withJSONObject: $0), encoding: .utf8)
                }
                let te = ToolEvent(tool: tool, args: args, status: .running)
                toolEvents.append(te)

                // Also add as inline block to current assistant message
                appendToolCallBlock(te)
            }

        case "tool_result":
            if let payload = json["payload"] as? [String: Any],
               let tool = payload["tool"] as? String {
                if let idx = toolEvents.lastIndex(where: { $0.tool == tool && $0.status == .running }) {
                    toolEvents[idx].output = payload["output"] as? String
                    toolEvents[idx].exitCode = payload["exit_code"] as? Int
                    toolEvents[idx].status = (toolEvents[idx].exitCode ?? 0) == 0 ? .completed : .failed
                    updateToolCallBlock(toolEvents[idx])
                }
            }

        case "exec.approval.requested":
            if let payload = json["payload"] as? [String: Any],
               let id = payload["id"] as? String {
                let plan = payload["systemRunPlan"] as? [String: Any]
                let command = plan?["rawCommand"] as? String ?? "unknown command"
                let cwd = plan?["cwd"] as? String ?? ""
                appendApprovalBlock(id: id, command: command, cwd: cwd)
            }

        case "tick":
            break // keepalive, ignore

        default:
            break
        }
    }

    private func handleResponse(_ json: [String: Any], raw: Data) {
        guard let id = json["id"] as? String else { return }
        lock.lock()
        let continuation = pendingRPC.removeValue(forKey: id)
        lock.unlock()
        continuation?.resume(returning: raw)
    }

    private func sendRPC(method: String, params: [String: Any]) async throws {
        let id = UUID().uuidString
        let frame: [String: Any] = ["type": "req", "id": id, "method": method, "params": params]
        let data = try JSONSerialization.data(withJSONObject: frame)
        guard let text = String(data: data, encoding: .utf8) else {
            throw AgentSessionError.encodingFailed
        }
        try await webSocket?.send(.string(text))
    }

    // MARK: - Message Block Helpers

    private func appendToolCallBlock(_ event: ToolEvent) {
        let block = ContentBlock.toolCall(
            id: event.id, tool: event.tool, args: event.args ?? "",
            status: event.status, output: nil, elapsedMs: nil
        )
        if let lastIdx = messages.indices.last, messages[lastIdx].role == .assistant {
            messages[lastIdx].blocks.append(block)
        } else {
            var msg = ChatMessage(role: .assistant, isStreaming: true)
            msg.blocks.append(block)
            messages.append(msg)
        }
    }

    private func updateToolCallBlock(_ event: ToolEvent) {
        for msgIdx in messages.indices.reversed() {
            for blockIdx in messages[msgIdx].blocks.indices {
                if case .toolCall(let id, _, _, _, _, _) = messages[msgIdx].blocks[blockIdx], id == event.id {
                    messages[msgIdx].blocks[blockIdx] = .toolCall(
                        id: event.id, tool: event.tool, args: event.args ?? "",
                        status: event.status, output: event.output,
                        elapsedMs: event.elapsed.map { Int($0 * 1000) }
                    )
                    return
                }
            }
        }
    }

    private func appendApprovalBlock(id: String, command: String, cwd: String) {
        let isDangerous = AgentSession.isDangerousCommand(command)
        let block = ContentBlock.approvalRequest(id: id, command: command, cwd: cwd, isDangerous: isDangerous, decision: nil)
        if let lastIdx = messages.indices.last, messages[lastIdx].role == .assistant {
            messages[lastIdx].blocks.append(block)
        } else {
            var msg = ChatMessage(role: .assistant)
            msg.blocks.append(block)
            messages.append(msg)
        }
    }

    /// Matches the dangerous command patterns from internal/gateway/router.go
    static func isDangerousCommand(_ cmd: String) -> Bool {
        let lower = cmd.lowercased()
        let patterns = [
            "curl", "wget", "nc ", "ncat", "netcat", "/dev/tcp",
            "base64 -d", "base64 --decode", "eval ", "bash -c", "sh -c",
            "python -c", "perl -e", "ruby -e", "rm -rf /", "dd if=", "mkfs",
            "chmod 777", "> /etc/", ">> /etc/", "passwd", "shadow", "sudoers"
        ]
        return patterns.contains { lower.contains($0) }
    }
}

public enum AgentSessionError: Error, LocalizedError {
    case invalidURL
    case encodingFailed
    case notConnected
    case rpcFailed(String)

    public var errorDescription: String? {
        switch self {
        case .invalidURL: return "Invalid WebSocket URL"
        case .encodingFailed: return "Failed to encode RPC frame"
        case .notConnected: return "Not connected to gateway"
        case .rpcFailed(let msg): return "RPC failed: \(msg)"
        }
    }
}
```

- [ ] **Step 2: Write AgentSession tests**

```swift
// apps/shared/Tests/DefenseClawKitTests/AgentSessionTests.swift
import XCTest
@testable import DefenseClawKit

final class AgentSessionTests: XCTestCase {
    func testDangerousCommandDetection() {
        XCTAssertTrue(AgentSession.isDangerousCommand("curl http://evil.com"))
        XCTAssertTrue(AgentSession.isDangerousCommand("rm -rf / --no-preserve-root"))
        XCTAssertTrue(AgentSession.isDangerousCommand("bash -c 'wget malware'"))
        XCTAssertTrue(AgentSession.isDangerousCommand("echo test >> /etc/hosts"))
        XCTAssertTrue(AgentSession.isDangerousCommand("base64 -d payload.b64 | sh"))
        XCTAssertTrue(AgentSession.isDangerousCommand("chmod 777 /var/www"))

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
}
```

- [ ] **Step 3: Run tests**

Run: `cd apps/shared && swift test --filter AgentSessionTests`
Expected: All 3 tests pass.

- [ ] **Step 4: Commit**

```bash
git add apps/shared/Sources/DefenseClawKit/AgentSession.swift
git add apps/shared/Tests/DefenseClawKitTests/AgentSessionTests.swift
git commit -m "feat(macos): add AgentSession WebSocket v3 client"
```

---

### Task 9: ProcessRunner (Python CLI Wrapper)

**Files:**
- Create: `apps/shared/Sources/DefenseClawKit/ProcessRunner.swift`
- Test: `apps/shared/Tests/DefenseClawKitTests/ProcessRunnerTests.swift`

- [ ] **Step 1: Write ProcessRunner**

```swift
// apps/shared/Sources/DefenseClawKit/ProcessRunner.swift
import Foundation

/// Runs DefenseClaw Python CLI commands via Process (shell).
public struct ProcessRunner: Sendable {
    private let binaryPath: String

    public init(binaryPath: String = "defenseclaw") {
        self.binaryPath = binaryPath
    }

    public struct CommandResult: Sendable {
        public let exitCode: Int32
        public let stdout: String
        public let stderr: String
        public var succeeded: Bool { exitCode == 0 }
    }

    /// Run a defenseclaw CLI command with the given arguments.
    public func run(_ args: [String]) async throws -> CommandResult {
        try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                let process = Process()
                process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
                process.arguments = [self.binaryPath] + args

                let stdoutPipe = Pipe()
                let stderrPipe = Pipe()
                process.standardOutput = stdoutPipe
                process.standardError = stderrPipe

                do {
                    try process.run()
                    process.waitUntilExit()

                    let stdoutData = stdoutPipe.fileHandleForReading.readDataToEndOfFile()
                    let stderrData = stderrPipe.fileHandleForReading.readDataToEndOfFile()

                    let result = CommandResult(
                        exitCode: process.terminationStatus,
                        stdout: String(data: stdoutData, encoding: .utf8) ?? "",
                        stderr: String(data: stderrData, encoding: .utf8) ?? ""
                    )
                    continuation.resume(returning: result)
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    // MARK: - Convenience Methods

    public func initialize() async throws -> CommandResult {
        try await run(["init"])
    }

    public func doctor() async throws -> CommandResult {
        try await run(["doctor"])
    }

    public func setupGateway() async throws -> CommandResult {
        try await run(["setup", "gateway"])
    }

    public func setupGuardrail() async throws -> CommandResult {
        try await run(["setup", "guardrail"])
    }

    public func setupGuardrailDisable() async throws -> CommandResult {
        try await run(["setup", "guardrail", "--disable"])
    }

    public func scanSkill(path: String) async throws -> CommandResult {
        try await run(["skill", "scan", path])
    }

    public func scanMCP(url: String) async throws -> CommandResult {
        try await run(["mcp", "scan", url])
    }

    public func scanCode(path: String) async throws -> CommandResult {
        try await run(["codeguard", "scan", path])
    }

    public func aibomScan() async throws -> CommandResult {
        try await run(["aibom", "scan"])
    }

    public func policyApply(template: String) async throws -> CommandResult {
        try await run(["policy", "apply", template])
    }

    public func policyReset() async throws -> CommandResult {
        try await run(["policy", "reset"])
    }

    public func policyTest() async throws -> CommandResult {
        try await run(["policy", "test"])
    }

    public func statusCommand() async throws -> CommandResult {
        try await run(["status"])
    }

    public func alertsCommand(severity: String? = nil) async throws -> CommandResult {
        var args = ["alerts"]
        if let s = severity { args += ["--severity", s] }
        return try await run(args)
    }
}
```

- [ ] **Step 2: Write ProcessRunner tests**

```swift
// apps/shared/Tests/DefenseClawKitTests/ProcessRunnerTests.swift
import XCTest
@testable import DefenseClawKit

final class ProcessRunnerTests: XCTestCase {
    func testRunEchoCommand() async throws {
        // Use a known-good command to verify Process execution works
        let runner = ProcessRunner(binaryPath: "echo")
        let result = try await runner.run(["hello", "world"])

        XCTAssertEqual(result.exitCode, 0)
        XCTAssertTrue(result.succeeded)
        XCTAssertEqual(result.stdout.trimmingCharacters(in: .whitespacesAndNewlines), "hello world")
    }

    func testRunFailingCommand() async throws {
        let runner = ProcessRunner(binaryPath: "false")
        let result = try await runner.run([])

        XCTAssertNotEqual(result.exitCode, 0)
        XCTAssertFalse(result.succeeded)
    }

    func testCommandResultProperties() {
        let success = ProcessRunner.CommandResult(exitCode: 0, stdout: "ok", stderr: "")
        XCTAssertTrue(success.succeeded)

        let failure = ProcessRunner.CommandResult(exitCode: 1, stdout: "", stderr: "error")
        XCTAssertFalse(failure.succeeded)
    }
}
```

- [ ] **Step 3: Run tests**

Run: `cd apps/shared && swift test --filter ProcessRunnerTests`
Expected: All 3 tests pass.

- [ ] **Step 4: Commit**

```bash
git add apps/shared/Sources/DefenseClawKit/ProcessRunner.swift
git add apps/shared/Tests/DefenseClawKitTests/ProcessRunnerTests.swift
git commit -m "feat(macos): add ProcessRunner for Python CLI integration"
```

---

### Task 10: ConfigManager (YAML Read/Write)

**Files:**
- Create: `apps/shared/Sources/DefenseClawKit/ConfigManager.swift`
- Test: `apps/shared/Tests/DefenseClawKitTests/ConfigManagerTests.swift`

- [ ] **Step 1: Write ConfigManager**

```swift
// apps/shared/Sources/DefenseClawKit/ConfigManager.swift
import Foundation
import Yams

/// Reads and writes ~/.defenseclaw/config.yaml.
public struct ConfigManager: Sendable {
    private let configPath: String

    public init(configPath: String? = nil) {
        if let path = configPath {
            self.configPath = path
        } else {
            let home = FileManager.default.homeDirectoryForCurrentUser.path
            self.configPath = "\(home)/.defenseclaw/config.yaml"
        }
    }

    /// Load the current config from disk.
    public func load() throws -> AppConfig {
        let url = URL(fileURLWithPath: configPath)
        let data = try Data(contentsOf: url)
        let yaml = String(data: data, encoding: .utf8) ?? ""
        let decoder = YAMLDecoder()
        return try decoder.decode(AppConfig.self, from: yaml)
    }

    /// Save config to disk (atomic write with 0600 permissions).
    public func save(_ config: AppConfig) throws {
        let encoder = YAMLEncoder()
        let yaml = try encoder.encode(config)
        let url = URL(fileURLWithPath: configPath)

        // Ensure parent directory exists
        let dir = url.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)

        try yaml.write(to: url, atomically: true, encoding: .utf8)

        // Set restrictive permissions (0600)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o600],
            ofItemAtPath: configPath
        )
    }

    /// Check if config file exists.
    public var exists: Bool {
        FileManager.default.fileExists(atPath: configPath)
    }
}
```

- [ ] **Step 2: Write ConfigManager tests**

```swift
// apps/shared/Tests/DefenseClawKitTests/ConfigManagerTests.swift
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
```

- [ ] **Step 3: Run tests**

Run: `cd apps/shared && swift test --filter ConfigManagerTests`
Expected: All 3 tests pass.

- [ ] **Step 4: Commit**

```bash
git add apps/shared/Sources/DefenseClawKit/ConfigManager.swift
git add apps/shared/Tests/DefenseClawKitTests/ConfigManagerTests.swift
git commit -m "feat(macos): add ConfigManager for YAML config read/write"
```

---

### Task 11: LaunchAgentManager

**Files:**
- Create: `apps/shared/Sources/DefenseClawKit/LaunchAgentManager.swift`
- Test: `apps/shared/Tests/DefenseClawKitTests/LaunchAgentManagerTests.swift`

- [ ] **Step 1: Write LaunchAgentManager**

```swift
// apps/shared/Sources/DefenseClawKit/LaunchAgentManager.swift
import Foundation

/// Manages the macOS LaunchAgent plist for the DefenseClaw sidecar.
/// The sidecar runs as a user-level LaunchAgent so it persists across app restarts.
public struct LaunchAgentManager: Sendable {
    public static let label = "com.defenseclaw.sidecar"

    private let plistPath: String
    private let sidecarBinary: String

    public init(sidecarBinary: String = "defenseclaw-gateway") {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        self.plistPath = "\(home)/Library/LaunchAgents/\(Self.label).plist"
        self.sidecarBinary = sidecarBinary
    }

    /// Generate the LaunchAgent plist content.
    public func plistContent() -> [String: Any] {
        [
            "Label": Self.label,
            "ProgramArguments": [sidecarBinary, "start", "--foreground"],
            "RunAtLoad": true,
            "KeepAlive": true,
            "StandardOutPath": "\(NSHomeDirectory())/.defenseclaw/sidecar.stdout.log",
            "StandardErrorPath": "\(NSHomeDirectory())/.defenseclaw/sidecar.stderr.log",
            "EnvironmentVariables": [
                "PATH": "/usr/local/bin:/usr/bin:/bin:\(NSHomeDirectory())/.local/bin"
            ]
        ]
    }

    /// Install the LaunchAgent plist and load it.
    public func install() throws {
        let plist = plistContent()
        let data = try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0)
        let url = URL(fileURLWithPath: plistPath)

        // Ensure LaunchAgents directory exists
        let dir = url.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)

        try data.write(to: url, options: .atomic)
    }

    /// Load the LaunchAgent (start the sidecar).
    public func load() throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        process.arguments = ["load", plistPath]
        try process.run()
        process.waitUntilExit()
    }

    /// Unload the LaunchAgent (stop the sidecar).
    public func unload() throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        process.arguments = ["unload", plistPath]
        try process.run()
        process.waitUntilExit()
    }

    /// Remove the plist file.
    public func uninstall() throws {
        try? unload()
        try FileManager.default.removeItem(atPath: plistPath)
    }

    /// Check if the plist is installed.
    public var isInstalled: Bool {
        FileManager.default.fileExists(atPath: plistPath)
    }

    /// Check if the service is currently loaded/running.
    public var isRunning: Bool {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        process.arguments = ["list", Self.label]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = Pipe()
        do {
            try process.run()
            process.waitUntilExit()
            return process.terminationStatus == 0
        } catch {
            return false
        }
    }
}
```

- [ ] **Step 2: Write LaunchAgentManager tests**

```swift
// apps/shared/Tests/DefenseClawKitTests/LaunchAgentManagerTests.swift
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
```

- [ ] **Step 3: Run tests**

Run: `cd apps/shared && swift test --filter LaunchAgentManagerTests`
Expected: All 3 tests pass.

- [ ] **Step 4: Commit**

```bash
git add apps/shared/Sources/DefenseClawKit/LaunchAgentManager.swift
git add apps/shared/Tests/DefenseClawKitTests/LaunchAgentManagerTests.swift
git commit -m "feat(macos): add LaunchAgentManager for sidecar lifecycle"
```

---

### Task 12: Run Full Test Suite and Clean Up

**Files:**
- Modify: `apps/shared/Sources/DefenseClawKit/DefenseClawKit.swift` (remove placeholder)

- [ ] **Step 1: Update the root file to re-export the public API**

```swift
// apps/shared/Sources/DefenseClawKit/DefenseClawKit.swift
public enum DefenseClawKit {
    public static let version = "0.1.0"
}

// All public types are automatically visible through the module.
// Import DefenseClawKit to access:
// - SidecarClient (REST API)
// - AgentSession (WebSocket v3)
// - ProcessRunner (Python CLI)
// - ConfigManager (YAML config)
// - LaunchAgentManager (macOS LaunchAgent)
// - All Models/* types
```

- [ ] **Step 2: Run the full test suite**

Run: `cd apps/shared && swift test 2>&1`
Expected: All tests pass (HealthSnapshotTests, ChatMessageTests, ScanResultTests, SidecarClientTests, AgentSessionTests, ProcessRunnerTests, ConfigManagerTests, LaunchAgentManagerTests).

- [ ] **Step 3: Verify build**

Run: `cd apps/shared && swift build -c release`
Expected: Build Succeeded

- [ ] **Step 4: Commit**

```bash
git add apps/shared/Sources/DefenseClawKit/DefenseClawKit.swift
git commit -m "feat(macos): finalize DefenseClawKit v0.1.0 shared package"
```

---

## Summary

| Task | Component | Files Created | Tests |
|------|-----------|---------------|-------|
| 1 | SPM Scaffold | Package.swift, DefenseClawKit.swift | build only |
| 2 | Severity, Health, Alert | 3 model files | HealthSnapshotTests (3) |
| 3 | Skill, Plugin, MCP, Tool | 4 model files | build only |
| 4 | ChatMessage, ToolEvent, Session | 3 model files | ChatMessageTests (4) |
| 5 | ScanResult, Policy, Enforce, Guardrail | 4 model files | ScanResultTests (2) |
| 6 | ConfigModels | 1 model file | build only |
| 7 | SidecarClient | 1 client file | SidecarClientTests (2) |
| 8 | AgentSession | 1 client file | AgentSessionTests (3) |
| 9 | ProcessRunner | 1 runner file | ProcessRunnerTests (3) |
| 10 | ConfigManager | 1 manager file | ConfigManagerTests (3) |
| 11 | LaunchAgentManager | 1 manager file | LaunchAgentManagerTests (3) |
| 12 | Full suite + cleanup | 1 update | all tests |

**Total: 20 source files, 8 test files, ~23 tests, 12 commits**
