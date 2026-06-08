import Foundation

public struct SessionConfig: Codable, Sendable {
    public var workspace: String
    public var agentName: String
    public var model: String?
    public var guardrailEnabled: Bool

    public init(workspace: String, agentName: String = "Agent", model: String? = nil, guardrailEnabled: Bool = true) {
        self.workspace = workspace; self.agentName = agentName; self.model = model; self.guardrailEnabled = guardrailEnabled
    }
}
