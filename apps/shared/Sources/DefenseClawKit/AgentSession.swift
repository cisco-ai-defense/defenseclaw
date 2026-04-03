import Foundation
import Observation

/// WebSocket v3 client for the OpenClaw gateway.
@Observable
public final class AgentSession: @unchecked Sendable {
    public private(set) var isConnected = false
    public private(set) var messages: [ChatMessage] = []
    public private(set) var toolEvents: [ToolEvent] = []

    private var webSocket: URLSessionWebSocketTask?
    private let urlSession = URLSession(configuration: .default)
    private let lock = NSLock()

    private let host: String
    private let port: Int
    private let token: String

    public init(host: String = "127.0.0.1", port: Int = 18789, token: String = "") {
        self.host = host; self.port = port; self.token = token
    }

    public func connect() async throws {
        guard let url = URL(string: "ws://\(host):\(port)") else { throw AgentSessionError.invalidURL }
        webSocket = urlSession.webSocketTask(with: url)
        webSocket?.resume()
        isConnected = true
        startReadLoop()
    }

    public func disconnect() {
        webSocket?.cancel(with: .goingAway, reason: nil)
        webSocket = nil
        isConnected = false
    }

    public func sendMessage(_ text: String) {
        let msg = ChatMessage.text(text, role: .user)
        messages.append(msg)
    }

    public func resolveApproval(requestId: String, approved: Bool) {
        let params: [String: Any] = ["id": requestId, "decision": approved ? "approved" : "denied"]
        Task { try? await sendRPC(method: "exec.approval.resolve", params: params) }
    }

    public func cancelStream() {
        Task { try? await sendRPC(method: "session.cancel", params: [:]) }
    }

    private func startReadLoop() {
        Task { [weak self] in
            guard let self else { return }
            while let ws = self.webSocket {
                do {
                    let message = try await ws.receive()
                    switch message {
                    case .string(let text): self.handleFrame(text)
                    case .data(let data):
                        if let text = String(data: data, encoding: .utf8) { self.handleFrame(text) }
                    @unknown default: break
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
        case "event": handleEvent(json)
        default: break
        }
    }

    private func handleEvent(_ json: [String: Any]) {
        guard let event = json["event"] as? String else { return }
        switch event {
        case "tool_call":
            if let payload = json["payload"] as? [String: Any], let tool = payload["tool"] as? String {
                let args = (payload["args"] as? [String: Any]).flatMap {
                    try? String(data: JSONSerialization.data(withJSONObject: $0), encoding: .utf8)
                }
                let te = ToolEvent(tool: tool, args: args, status: .running)
                toolEvents.append(te)
                appendToolCallBlock(te)
            }
        case "tool_result":
            if let payload = json["payload"] as? [String: Any], let tool = payload["tool"] as? String {
                if let idx = toolEvents.lastIndex(where: { $0.tool == tool && $0.status == .running }) {
                    toolEvents[idx].output = payload["output"] as? String
                    toolEvents[idx].exitCode = payload["exit_code"] as? Int
                    toolEvents[idx].status = (toolEvents[idx].exitCode ?? 0) == 0 ? .completed : .failed
                    updateToolCallBlock(toolEvents[idx])
                }
            }
        case "exec.approval.requested":
            if let payload = json["payload"] as? [String: Any], let id = payload["id"] as? String {
                let plan = payload["systemRunPlan"] as? [String: Any]
                let command = plan?["rawCommand"] as? String ?? "unknown command"
                let cwd = plan?["cwd"] as? String ?? ""
                appendApprovalBlock(id: id, command: command, cwd: cwd)
            }
        case "tick", "connect.challenge": break
        default: break
        }
    }

    private func sendRPC(method: String, params: [String: Any]) async throws {
        let id = UUID().uuidString
        let frame: [String: Any] = ["type": "req", "id": id, "method": method, "params": params]
        let data = try JSONSerialization.data(withJSONObject: frame)
        guard let text = String(data: data, encoding: .utf8) else { throw AgentSessionError.encodingFailed }
        try await webSocket?.send(.string(text))
    }

    private func appendToolCallBlock(_ event: ToolEvent) {
        let block = ContentBlock.toolCall(id: event.id, tool: event.tool, args: event.args ?? "", status: event.status, output: nil, elapsedMs: nil)
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
    case invalidURL, encodingFailed, notConnected, rpcFailed(String)
    public var errorDescription: String? {
        switch self {
        case .invalidURL: return "Invalid WebSocket URL"
        case .encodingFailed: return "Failed to encode RPC frame"
        case .notConnected: return "Not connected to gateway"
        case .rpcFailed(let msg): return "RPC failed: \(msg)"
        }
    }
}
