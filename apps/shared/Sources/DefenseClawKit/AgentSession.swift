import Foundation
import Observation

/// WebSocket v3 client for the OpenClaw gateway.
@Observable
public final class AgentSession: @unchecked Sendable {
    public private(set) var isConnected = false
    public private(set) var messages: [ChatMessage] = []
    public private(set) var toolEvents: [ToolEvent] = []
    public private(set) var activeSessionKey: String?

    private var webSocket: URLSessionWebSocketTask?
    private let urlSession = URLSession(configuration: .default)
    private let lock = NSLock()
    private var pendingRPC: [String: CheckedContinuation<[String: Any], any Error>] = [:]

    private let host: String
    private let port: Int
    private let token: String
    private let log = AppLogger.shared
    private var device: DeviceIdentity?
    private var reconnectTask: Task<Void, Never>?
    private var shouldReconnect = true
    private var reconnectAttempt = 0

    public init(host: String = "127.0.0.1", port: Int = 18789, token: String = "") {
        self.host = host; self.port = port
        // Auto-discover token if not provided — check DefenseClaw config, then OpenClaw config
        if token.isEmpty {
            var resolved: String? = nil
            if let config = try? ConfigManager().load() {
                resolved = config.gateway?.token
                if resolved == nil || resolved?.isEmpty == true, let envName = config.gateway?.tokenEnv, !envName.isEmpty {
                    resolved = ProcessInfo.processInfo.environment[envName]
                }
            }
            if resolved == nil || resolved?.isEmpty == true {
                resolved = SidecarClient.readOpenClawGatewayToken()
            }
            self.token = resolved ?? ""
            if self.token.isEmpty {
                AppLogger.shared.warn("gateway", "No auth token found — gateway connect will likely fail")
            } else {
                AppLogger.shared.info("gateway", "Auth token loaded for gateway", details: "len=\(self.token.count)")
            }
        } else {
            self.token = token
        }
        // Load or create a separate device identity for the macOS app.
        // Uses a different key file than the sidecar (device.key) to avoid
        // conflicting connections on the same gateway.
        do {
            let home = FileManager.default.homeDirectoryForCurrentUser.path
            let appKeyFile = "\(home)/.defenseclaw/app-device.key"
            self.device = try DeviceIdentity.loadOrCreate(keyFile: appKeyFile)
            AppLogger.shared.info("gateway", "App device identity loaded", details: "id=\(self.device!.deviceID.prefix(16))...")
        } catch {
            AppLogger.shared.warn("gateway", "Device identity unavailable", details: "\(error)")
        }
    }

    public func connect() async throws {
        shouldReconnect = true
        reconnectAttempt = 0
        reconnectTask?.cancel()
        reconnectTask = nil
        try await connectOnce()
    }

    private func connectOnce() async throws {
        let target = "ws://\(host):\(port)"
        log.info("gateway", "Connecting to \(target)")
        guard let url = URL(string: target) else { throw AgentSessionError.invalidURL }

        // Clean up previous socket
        webSocket?.cancel(with: .goingAway, reason: nil)
        webSocket = urlSession.webSocketTask(with: url)
        webSocket?.resume()
        log.info("gateway", "WebSocket opened, waiting for challenge")

        // Fail any pending RPCs from previous connection
        lock.lock()
        let stale = pendingRPC
        pendingRPC.removeAll()
        lock.unlock()
        for (_, cont) in stale {
            cont.resume(throwing: AgentSessionError.notConnected)
        }

        startReadLoop()
    }

    public func disconnect() {
        log.info("gateway", "Disconnecting from gateway")
        shouldReconnect = false
        reconnectTask?.cancel()
        reconnectTask = nil
        webSocket?.cancel(with: .goingAway, reason: nil)
        webSocket = nil
        isConnected = false
    }

    /// Schedule an auto-reconnect with exponential backoff (1s, 2s, 4s, 8s… max 30s).
    private func scheduleReconnect() {
        guard shouldReconnect else { return }
        reconnectTask?.cancel()
        reconnectTask = Task { [weak self] in
            guard let self else { return }
            let delay = min(30.0, pow(2.0, Double(self.reconnectAttempt)))
            self.log.info("gateway", "Reconnecting in \(Int(delay))s (attempt \(self.reconnectAttempt + 1))")
            await MainActor.run {
                self.isConnected = false
            }
            do {
                try await Task.sleep(for: .seconds(delay))
            } catch { return } // cancelled

            self.reconnectAttempt += 1
            do {
                try await self.connectOnce()
            } catch {
                self.log.warn("gateway", "Reconnect failed", details: "\(error)")
                self.scheduleReconnect()
            }
        }
    }

    /// Send a user chat message via the `chat.send` RPC method.
    ///
    /// **Protocol** (from OpenClaw gateway / BlueClaw reference):
    /// ```json
    /// { "type": "req", "id": "<uuid>", "method": "chat.send", "params": {
    ///     "sessionKey": "<active-session>",
    ///     "message": "<user-text>",
    ///     "idempotencyKey": "<uuid>"
    /// }}
    /// ```
    /// Response comes as streaming `chat` events with states: delta, final, error, aborted.
    public func sendMessage(_ text: String) {
        log.info("gateway", "Sending user message", details: "\(text.prefix(100))")
        let msg = ChatMessage.text(text, role: .user)
        messages.append(msg)

        guard isConnected else {
            Task { @MainActor in
                appendSystemNote("Gateway offline — message queued locally")
            }
            return
        }

        Task {
            do {
                let params: [String: Any] = [
                    "sessionKey": activeSessionKey ?? "",
                    "message": text,
                    "idempotencyKey": UUID().uuidString,
                ]
                log.info("gateway", "chat.send RPC", details: "sessionKey=\(activeSessionKey ?? "nil") msg=\(text.prefix(80))")
                let resp = try await sendRPCAsync(method: "chat.send", params: params)
                log.info("gateway", "chat.send RPC OK", details: "keys=\(resp.keys)")
            } catch {
                log.error("gateway", "chat.send RPC failed", details: "\(error)")
                await MainActor.run {
                    appendSystemNote("Failed to send: \(error.localizedDescription)")
                }
            }
        }
    }

    public func resolveApproval(requestId: String, approved: Bool) {
        let params: [String: Any] = ["id": requestId, "decision": approved ? "allow-once" : "deny"]
        Task { try? await sendRPCAsync(method: "exec.approval.resolve", params: params) }
    }

    public func cancelStream() {
        Task { try? await sendRPCAsync(method: "session.cancel", params: [:]) }
    }

    // MARK: - Read Loop

    private func startReadLoop() {
        Task { [weak self] in
            guard let self else { return }
            while let ws = self.webSocket {
                do {
                    let message = try await ws.receive()
                    switch message {
                    case .string(let text):
                        self.log.debug("gateway", "← WS frame", details: "\(text.prefix(500))")
                        await self.handleFrame(text)
                    case .data(let data):
                        if let text = String(data: data, encoding: .utf8) {
                            self.log.debug("gateway", "← WS frame (data)", details: "\(text.prefix(500))")
                            await self.handleFrame(text)
                        }
                    @unknown default: break
                    }
                } catch {
                    self.log.warn("gateway", "WebSocket read loop ended", details: "\(error)")
                    await MainActor.run { self.isConnected = false }
                    self.scheduleReconnect()
                    return
                }
            }
        }
    }

    @MainActor
    private func handleFrame(_ text: String) {
        guard let data = text.data(using: .utf8),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let type = json["type"] as? String else { return }

        switch type {
        case "event":
            handleEvent(json)
        case "res":
            handleResponse(json)
        default:
            break
        }
    }

    // MARK: - Event Handling

    @MainActor
    private func handleEvent(_ json: [String: Any]) {
        guard let event = json["event"] as? String else { return }

        switch event {
        case "connect.challenge":
            handleConnectChallenge(json)
        case "tool_call":
            handleToolCallEvent(json)
        case "tool_result":
            handleToolResultEvent(json)
        case "exec.approval.requested":
            handleApprovalEvent(json)
        case "session.message":
            handleSessionMessage(json)
        case "session.tool":
            handleSessionTool(json)
        case "agent":
            handleAgentEvent(json)
        case "chat":
            handleChatEvent(json)
        case "sessions.changed":
            handleSessionsChanged(json)
        case "tick", "health", "presence", "heartbeat":
            break
        default:
            log.debug("gateway", "Unhandled event: \(event)")
        }
    }

    // MARK: - Connect Handshake (v3 protocol)

    @MainActor
    private func handleConnectChallenge(_ json: [String: Any]) {
        guard let payload = json["payload"] as? [String: Any],
              let nonce = payload["nonce"] as? String else {
            log.error("gateway", "Invalid connect.challenge payload")
            return
        }

        Task {
            do {
                // Use a distinct client identity from the DefenseClaw sidecar
                // (sidecar uses "gateway-client" / "backend"). Using a different
                // ID ensures the OpenClaw gateway treats this as a separate client
                // and doesn't conflict with or replace the sidecar connection.
                let clientID = "defenseclaw-macos-app"
                let clientMode = "operator-ui"
                let role = "operator"
                let scopes = ["operator.read", "operator.write", "operator.admin", "operator.approvals"]

                var connectParams: [String: Any] = [
                    "minProtocol": 3,
                    "maxProtocol": 3,
                    "client": [
                        "id": clientID,
                        "version": "1.0.0",
                        "platform": "darwin",
                        "mode": clientMode,
                    ] as [String: Any],
                    "role": role,
                    "scopes": scopes,
                    "caps": ["tool-events", "session-events"],
                    "auth": [
                        "token": token,
                    ] as [String: Any],
                    "userAgent": "defenseclaw-macos/1.0.0",
                    "locale": "en-US",
                ]

                // Add device identity block for challenge-response auth
                if let device {
                    connectParams["device"] = device.connectDevice(
                        clientID: clientID, clientMode: clientMode, role: role,
                        scopes: scopes, token: token, nonce: nonce, platform: "darwin"
                    )
                    log.info("gateway", "Device identity included in connect", details: "id=\(device.deviceID.prefix(16))...")
                } else {
                    log.warn("gateway", "No device identity — connect may be rejected")
                }

                let response = try await sendRPCAsync(method: "connect", params: connectParams)
                log.info("gateway", "Connect handshake OK", details: "keys=\(response.keys)")

                await MainActor.run {
                    self.isConnected = true
                }
                self.reconnectAttempt = 0

                // Subscribe to active sessions
                await subscribeToSessions()
            } catch {
                log.error("gateway", "Connect handshake failed", details: "\(error)")
                await MainActor.run {
                    self.isConnected = false
                }
            }
        }
    }

    private func subscribeToSessions() async {
        do {
            let sessionsResp = try await sendRPCAsync(method: "sessions.list", params: [:])
            log.info("gateway", "sessions.list response", details: "keys=\(sessionsResp.keys)")

            // Extract session IDs from response (may be array or map)
            var sessionIDs: [String] = []

            if let sessions = sessionsResp["sessions"] as? [[String: Any]] {
                sessionIDs = sessions.compactMap { $0["id"] as? String }
            } else if let sessions = sessionsResp["sessions"] as? [String: Any] {
                sessionIDs = Array(sessions.keys)
            }
            // Also try payload as direct array
            if sessionIDs.isEmpty {
                for (key, _) in sessionsResp {
                    if key != "type" && key != "id" && key != "ok" {
                        sessionIDs.append(key)
                    }
                }
            }

            for sessionID in sessionIDs {
                do {
                    _ = try await sendRPCAsync(method: "sessions.subscribe", params: ["sessionId": sessionID])
                    _ = try? await sendRPCAsync(method: "sessions.messages.subscribe", params: ["sessionId": sessionID])
                    log.info("gateway", "Subscribed to session \(sessionID)")
                    await MainActor.run {
                        if self.activeSessionKey == nil {
                            self.activeSessionKey = sessionID
                        }
                    }
                } catch {
                    log.warn("gateway", "Subscribe failed for \(sessionID)", details: "\(error)")
                }
            }
        } catch {
            log.warn("gateway", "sessions.list failed", details: "\(error)")
        }
    }

    // MARK: - Session Message Handling

    @MainActor
    private func handleSessionMessage(_ json: [String: Any]) {
        guard let payload = json["payload"] as? [String: Any] else { return }

        // Track session key
        if let sessionKey = payload["sessionKey"] as? String, activeSessionKey == nil {
            activeSessionKey = sessionKey
        }

        // Format A: chat message {message: {role, content, ...}}
        if let message = payload["message"] as? [String: Any] {
            let role = message["role"] as? String ?? "assistant"
            let messageRole: MessageRole = role == "user" ? .user : .assistant

            // Extract content — can be string or array of content blocks
            var textContent = ""
            if let content = message["content"] as? String {
                textContent = content
            } else if let contentBlocks = message["content"] as? [[String: Any]] {
                textContent = contentBlocks.compactMap { block -> String? in
                    if let text = block["text"] as? String { return text }
                    return nil
                }.joined()
            }

            if !textContent.isEmpty && messageRole == .assistant {
                log.info("gateway", "Received assistant message", details: "\(textContent.prefix(120))")
                // Check if last message is assistant and streaming — append to it
                if let lastIdx = messages.indices.last,
                   messages[lastIdx].role == .assistant,
                   messages[lastIdx].isStreaming {
                    // Update text content of streaming message
                    messages[lastIdx].blocks = [.text(id: UUID().uuidString, text: textContent)]
                } else {
                    let chatMsg = ChatMessage.text(textContent, role: .assistant)
                    messages.append(chatMsg)
                }
            }

            // Check for error
            if let stopReason = message["stopReason"] as? String, stopReason == "error" {
                let errorMsg = message["error"] as? String ?? "Unknown error"
                appendSystemNote("Agent error: \(errorMsg)")
            }
            return
        }

        // Format B: tool stream {stream: "tool", data: {...}}
        if let stream = payload["stream"] as? String, stream == "tool" || stream == "lifecycle" {
            handleSessionToolStream(payload)
        }
    }

    @MainActor
    private func handleSessionTool(_ json: [String: Any]) {
        guard let payload = json["payload"] as? [String: Any] else { return }
        handleSessionToolStream(payload)
    }

    @MainActor
    private func handleSessionToolStream(_ payload: [String: Any]) {
        let data = payload["data"] as? [String: Any] ?? payload

        let toolType = data["type"] as? String ?? data["phase"] as? String ?? ""
        let toolName = data["name"] as? String ?? data["tool"] as? String ?? "unknown"

        if toolType == "call" || toolType == "tool_call" {
            let args = (data["args"] as? [String: Any]).flatMap {
                try? String(data: JSONSerialization.data(withJSONObject: $0), encoding: .utf8)
            } ?? (data["input"] as? [String: Any]).flatMap {
                try? String(data: JSONSerialization.data(withJSONObject: $0), encoding: .utf8)
            }
            let te = ToolEvent(tool: toolName, args: args, status: .running)
            toolEvents.append(te)
            appendToolCallBlock(te)
        } else if toolType == "result" || toolType == "tool_result" {
            let output = data["output"] as? String ?? data["result"] as? String
            let exitCode = data["exit_code"] as? Int ?? data["exitCode"] as? Int
            if let idx = toolEvents.lastIndex(where: { $0.tool == toolName && $0.status == .running }) {
                toolEvents[idx].output = output
                toolEvents[idx].exitCode = exitCode
                toolEvents[idx].status = (exitCode ?? 0) == 0 ? .completed : .failed
                updateToolCallBlock(toolEvents[idx])
            }
        }
    }

    @MainActor
    private func handleAgentEvent(_ json: [String: Any]) {
        guard let payload = json["payload"] as? [String: Any] else { return }

        // Stream format: {stream: "text", data: {content: "..."}}
        if let stream = payload["stream"] as? String {
            if stream == "text", let data = payload["data"] as? [String: Any],
               let content = data["content"] as? String {
                // Streaming text from assistant
                if let lastIdx = messages.indices.last,
                   messages[lastIdx].role == .assistant,
                   messages[lastIdx].isStreaming {
                    let existing = messages[lastIdx].textContent
                    messages[lastIdx].blocks = [.text(id: UUID().uuidString, text: existing + content)]
                } else {
                    var msg = ChatMessage(role: .assistant, isStreaming: true)
                    msg.blocks = [.text(id: UUID().uuidString, text: content)]
                    messages.append(msg)
                }
            } else if stream == "tool" {
                handleSessionToolStream(payload)
            } else if stream == "lifecycle", let data = payload["data"] as? [String: Any] {
                let phase = data["phase"] as? String ?? ""
                if phase == "done" || phase == "complete" || phase == "end" {
                    // Mark last streaming message as complete
                    if let lastIdx = messages.indices.last,
                       messages[lastIdx].isStreaming {
                        messages[lastIdx].isStreaming = false
                    }
                }
            }
            return
        }

        // Legacy format with toolCall/toolResult
        if let toolCall = payload["toolCall"] as? [String: Any] {
            let name = toolCall["name"] as? String ?? toolCall["tool"] as? String ?? "unknown"
            let args = (toolCall["args"] as? [String: Any]).flatMap {
                try? String(data: JSONSerialization.data(withJSONObject: $0), encoding: .utf8)
            }
            let te = ToolEvent(tool: name, args: args, status: .running)
            toolEvents.append(te)
            appendToolCallBlock(te)
        }

        if let toolResult = payload["toolResult"] as? [String: Any] {
            let name = toolResult["name"] as? String ?? toolResult["tool"] as? String ?? "unknown"
            if let idx = toolEvents.lastIndex(where: { $0.tool == name && $0.status == .running }) {
                toolEvents[idx].output = toolResult["output"] as? String
                toolEvents[idx].exitCode = toolResult["exitCode"] as? Int
                toolEvents[idx].status = (toolEvents[idx].exitCode ?? 0) == 0 ? .completed : .failed
                updateToolCallBlock(toolEvents[idx])
            }
        }
    }

    @MainActor
    private func handleChatEvent(_ json: [String: Any]) {
        guard let payload = json["payload"] as? [String: Any] else { return }
        let state = payload["state"] as? String ?? ""
        let sessionKey = payload["sessionKey"] as? String

        if let sessionKey, activeSessionKey == nil {
            activeSessionKey = sessionKey
        }

        switch state {
        case "running", "streaming":
            // Agent is processing — mark last assistant message as streaming
            if messages.last?.role != .assistant || messages.last?.isStreaming != true {
                var msg = ChatMessage(role: .assistant, isStreaming: true)
                msg.blocks = []
                messages.append(msg)
            }
        case "done", "complete", "idle":
            // Mark streaming complete
            if let lastIdx = messages.indices.last, messages[lastIdx].isStreaming {
                messages[lastIdx].isStreaming = false
            }
        case "error":
            let errorMsg = payload["errorMessage"] as? String ?? "Unknown error"
            appendSystemNote("Chat error: \(errorMsg)")
            if let lastIdx = messages.indices.last, messages[lastIdx].isStreaming {
                messages[lastIdx].isStreaming = false
            }
        default:
            break
        }
    }

    @MainActor
    private func handleSessionsChanged(_ json: [String: Any]) {
        guard let payload = json["payload"] as? [String: Any] else { return }
        if let sessionKey = payload["sessionKey"] as? String, activeSessionKey == nil {
            activeSessionKey = sessionKey
            Task { await subscribeToSessions() }
        }
    }

    // MARK: - Tool Call/Result Events (legacy direct format)

    @MainActor
    private func handleToolCallEvent(_ json: [String: Any]) {
        if let payload = json["payload"] as? [String: Any], let tool = payload["tool"] as? String {
            let args = (payload["args"] as? [String: Any]).flatMap {
                try? String(data: JSONSerialization.data(withJSONObject: $0), encoding: .utf8)
            }
            let te = ToolEvent(tool: tool, args: args, status: .running)
            toolEvents.append(te)
            appendToolCallBlock(te)
        }
    }

    @MainActor
    private func handleToolResultEvent(_ json: [String: Any]) {
        if let payload = json["payload"] as? [String: Any], let tool = payload["tool"] as? String {
            if let idx = toolEvents.lastIndex(where: { $0.tool == tool && $0.status == .running }) {
                toolEvents[idx].output = payload["output"] as? String
                toolEvents[idx].exitCode = payload["exit_code"] as? Int
                toolEvents[idx].status = (toolEvents[idx].exitCode ?? 0) == 0 ? .completed : .failed
                updateToolCallBlock(toolEvents[idx])
            }
        }
    }

    @MainActor
    private func handleApprovalEvent(_ json: [String: Any]) {
        if let payload = json["payload"] as? [String: Any], let id = payload["id"] as? String {
            let plan = payload["systemRunPlan"] as? [String: Any]
                ?? (payload["request"] as? [String: Any])?["systemRunPlan"] as? [String: Any]
            let command = plan?["rawCommand"] as? String
                ?? (payload["request"] as? [String: Any])?["command"] as? String
                ?? "unknown command"
            let cwd = plan?["cwd"] as? String
                ?? (payload["request"] as? [String: Any])?["cwd"] as? String
                ?? ""
            appendApprovalBlock(id: id, command: command, cwd: cwd)
        }
    }

    // MARK: - RPC Response Handling

    @MainActor
    private func handleResponse(_ json: [String: Any]) {
        guard let id = json["id"] as? String else { return }
        lock.lock()
        let continuation = pendingRPC.removeValue(forKey: id)
        lock.unlock()

        if let continuation {
            let ok = json["ok"] as? Bool ?? false
            if ok {
                continuation.resume(returning: json)
            } else {
                let errorMsg = (json["error"] as? [String: Any])?["message"] as? String ?? "RPC failed"
                continuation.resume(throwing: AgentSessionError.rpcFailed(errorMsg))
            }
        }
    }

    // MARK: - RPC Send

    private func sendRPCAsync(method: String, params: [String: Any]) async throws -> [String: Any] {
        let id = UUID().uuidString
        let frame: [String: Any] = ["type": "req", "id": id, "method": method, "params": params]
        let data = try JSONSerialization.data(withJSONObject: frame)
        guard let text = String(data: data, encoding: .utf8) else { throw AgentSessionError.encodingFailed }

        return try await withCheckedThrowingContinuation { continuation in
            lock.lock()
            pendingRPC[id] = continuation
            lock.unlock()

            Task {
                do {
                    try await webSocket?.send(.string(text))
                } catch {
                    lock.lock()
                    let cont = pendingRPC.removeValue(forKey: id)
                    lock.unlock()
                    cont?.resume(throwing: error)
                }
            }

            // Timeout after 30 seconds
            Task {
                try? await Task.sleep(for: .seconds(30))
                lock.lock()
                let cont = pendingRPC.removeValue(forKey: id)
                lock.unlock()
                cont?.resume(throwing: AgentSessionError.rpcFailed("timeout"))
            }
        }
    }

    // MARK: - Message Helpers

    @MainActor
    private func appendSystemNote(_ text: String) {
        let msg = ChatMessage.text(text, role: .system)
        messages.append(msg)
    }

    @MainActor
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

    @MainActor
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

    @MainActor
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
