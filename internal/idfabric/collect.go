// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package idfabric

import (
	"encoding/json"
	"os"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// EnableEnv force-enables capture outside managed enterprise mode so the
// branch can be exercised on a test endpoint.
const EnableEnv = "DEFENSECLAW_IDFABRIC_SPOOL"

// discoveryBudget bounds MCP configuration discovery on session_start. The
// hook is on the agent's critical path, so an unreadable or pathological
// config tree degrades the record to "partial" instead of delaying the
// guardrail.
const discoveryBudget = 250 * time.Millisecond

// eventLabelInventory names the synthetic source of an inventory record, which
// has no hook event of its own.
const eventLabelInventory = "inventory"

// Enabled reports whether Identity Fabric capture should run.
//
// Capture is a managed-enterprise feature. The environment override exists for
// validating this branch on a test endpoint and is not a supported
// configuration surface.
func Enabled(deploymentMode string, managedEnterpriseHook bool) bool {
	if isTruthy(os.Getenv(EnableEnv)) {
		return true
	}
	if managedEnterpriseHook {
		return true
	}
	if managed.IsManagedEnterprise(deploymentMode) {
		return true
	}
	return managed.IsManagedEnterprise(managed.PinnedDeploymentMode())
}

func isTruthy(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// HookContext is everything the hook process knows about one invocation.
type HookContext struct {
	// Connector is DefenseClaw's connector name, e.g. "claudecode".
	Connector string
	// Event is the connector-native hook event name, e.g. "PreToolUse".
	Event string
	// Payload is the agent's raw hook JSON.
	Payload []byte
	// Home is the resolved DefenseClaw home for this user.
	Home string
	// ManagedEnterprise marks an administrator-enrolled hook.
	ManagedEnterprise bool
	// ProducerVersion identifies the build emitting the record.
	ProducerVersion string
	// ReceivedAt is when the hook received the event.
	ReceivedAt time.Time
}

// CaptureHookEvent writes the records DefenseClaw would send to AI Defense for
// one hook invocation, returning the files written.
//
// Unsupported connectors and events are skipped with no error: this is a
// telemetry side effect and must never influence the guardrail outcome.
func CaptureHookEvent(hc HookContext) ([]string, error) {
	platform, ok := PlatformForConnector(hc.Connector)
	if !ok {
		return nil, nil
	}
	fields := parseHookPayload(hc.Payload)
	// Claude Code omits the CLI event flag and names the event in the payload
	// instead, so the flag is preferred and the payload is the fallback.
	kind, ok := eventKind(firstNonBlank(hc.Event, fields.hookEventName))
	if !ok {
		return nil, nil
	}
	receivedAt := hc.ReceivedAt
	if receivedAt.IsZero() {
		receivedAt = time.Now()
	}
	receivedAt = receivedAt.UTC()

	common := EventCommon{
		EventType: kind,
		SessionID: fields.sessionID,
		Model:     fields.model,
		Agent: Agent{
			Platform:        platform,
			PlatformVersion: fields.platformVersion(platform),
			ProcessType:     ProcessTypeForPlatform(platform),
		},
		User:   collectUser(platform, hc.Home, hc.Payload),
		Device: collectDevice(hc.Home),
	}
	common.EventTime, common.TimeSource = resolveEventTime(fields.timestamp, receivedAt)

	spool, err := NewSpool()
	if err != nil {
		return nil, err
	}

	var written []string
	switch kind {
	case EventTypeSessionStart:
		// The budget is measured from now, not from receivedAt: that timestamp
		// describes when the agent's event arrived and can lag well behind this
		// call under clock skew or a slow hook start. Deriving the deadline
		// from it would leave discovery already out of budget and report an
		// error for a config tree that was never read.
		discovery := DiscoverMCPServers(
			platform,
			fields.cwd,
			time.Now().Add(discoveryBudget),
		)
		discoveredAt := discovery.DiscoveredAt
		event := AgentEvent{
			Metadata: NewMetadata(SchemaModelAgentEvent, hc.ProducerVersion, receivedAt),
			SessionStart: &SessionStart{
				EventCommon:        common,
				MCPDiscoveryStatus: discovery.Status,
				MCPDiscoveredAt:    &discoveredAt,
				MCPServers:         nonNilServers(discovery.Servers),
			},
		}
		path, err := spool.Write(Source{
			Model:     SchemaModelAgentEvent,
			Connector: hc.Connector,
			Event:     string(EventTypeSessionStart),
		}, receivedAt, event)
		if err != nil {
			return written, err
		}
		written = append(written, path)

		// The aggregated inventory shares this pass's discovery rather than
		// re-reading the same files a second time.
		enforceable := policyEnforceable(hc)
		inventory := AgentRecord{
			Metadata: NewMetadata(SchemaModelAgent, hc.ProducerVersion, receivedAt),
			// The hook is executing inside the agent's own event, which is a
			// same-scan observation that the platform is running for this user.
			RuntimeStatus:       RuntimeStatusRunning,
			IsPolicyEnforceable: &enforceable,
			Agent:               common.Agent,
			User:                common.User,
			Device:              common.Device,
			MCPServers:          nonNilServers(discovery.Servers),
		}
		path, err = spool.Write(Source{
			Model:     SchemaModelAgent,
			Connector: hc.Connector,
			Event:     eventLabelInventory,
		}, receivedAt, inventory)
		if err != nil {
			return written, err
		}
		written = append(written, path)

	case EventTypePreToolUse:
		event := AgentEvent{
			Metadata: NewMetadata(SchemaModelAgentEvent, hc.ProducerVersion, receivedAt),
			PreToolUse: &PreToolUse{
				EventCommon:   common,
				ToolName:      fields.toolName,
				MCPServerName: fields.mcpServerName(),
			},
		}
		path, err := spool.Write(Source{
			Model:     SchemaModelAgentEvent,
			Connector: hc.Connector,
			Event:     string(EventTypePreToolUse),
		}, receivedAt, event)
		if err != nil {
			return written, err
		}
		written = append(written, path)
	}

	return written, nil
}

// policyEnforceable reports the observation-time enforcement capability.
//
// It is deliberately conservative and true only for an administrator-enrolled
// managed hook: that registration is tamper-resistant and its healthy state is
// demonstrated by this very invocation. An ordinary user-scope hook is
// reported false because the user can remove it between executions. This is a
// capability snapshot, never a promise about later executions.
//
// Note that the hook process cannot see whether the active policy mode permits
// intervention, so a managed hook running in observe-only mode is still
// reported true. Deciding that accurately needs the sidecar's policy view.
func policyEnforceable(hc HookContext) bool {
	return hc.ManagedEnterprise
}

// nonNilServers keeps mcp_servers a present JSON array rather than null, so a
// consumer can distinguish "no servers configured" from "field absent".
func nonNilServers(servers []MCPServer) []MCPServer {
	if servers == nil {
		return []MCPServer{}
	}
	return servers
}

// collectUser assembles the user block. The OS join key always comes from the
// process token; only the email may come from agent-supplied data.
func collectUser(platform Platform, home string, payload []byte) User {
	out := OSIdentity()
	if email, err := UserEmailForConnector(platform, home, payload); err == nil {
		out.AuthenticatedUserEmail = email
	}
	return out
}

// collectDevice assembles the device block. A missing device key yields an
// empty id rather than a fabricated one.
func collectDevice(home string) Device {
	out := Device{
		Username:        osUsername(),
		OperatingSystem: HostOperatingSystem(),
	}
	if id, err := DeviceFingerprint(DefaultDeviceKeyFile(home)); err == nil {
		out.ID = id
	}
	if hostname, err := os.Hostname(); err == nil {
		out.Hostname = strings.TrimSpace(hostname)
	}
	return out
}

// resolveEventTime prefers a trustworthy agent-reported time and otherwise
// falls back to hook receipt, recording which was used.
func resolveEventTime(agentTime string, receivedAt time.Time) (time.Time, TimeSource) {
	trimmed := strings.TrimSpace(agentTime)
	if trimmed != "" {
		if parsed, err := time.Parse(time.RFC3339, trimmed); err == nil {
			return parsed.UTC(), TimeSourceAgent
		}
	}
	return receivedAt, TimeSourceHookReceipt
}

// PlatformForConnector maps a DefenseClaw connector name to an Astrix
// platform. Connectors outside the current scope are not captured.
func PlatformForConnector(connector string) (Platform, bool) {
	switch strings.ToLower(strings.TrimSpace(connector)) {
	case "claudecode":
		return PlatformClaudeCode, true
	case "codex":
		return PlatformCodex, true
	case "cursor":
		return PlatformCursor, true
	default:
		return "", false
	}
}

// eventKind maps a connector-native event name to the captured event type.
//
// The three connectors spell these differently (PascalCase for Codex and
// Claude Code, camelCase for Cursor), so comparison is done on a folded form.
func eventKind(event string) (EventType, bool) {
	switch foldEventName(event) {
	case "sessionstart":
		return EventTypeSessionStart, true
	case "pretooluse":
		return EventTypePreToolUse, true
	default:
		return "", false
	}
}

// foldEventName lowercases and removes separators so SessionStart,
// sessionStart, and session_start compare equal.
func foldEventName(event string) string {
	var b strings.Builder
	for _, r := range strings.TrimSpace(event) {
		switch r {
		case '_', '-', '.', ' ':
			continue
		}
		if r >= 'A' && r <= 'Z' {
			r += 'a' - 'A'
		}
		b.WriteRune(r)
	}
	return b.String()
}

// hookPayloadFields is the allow-listed projection of an agent hook payload.
// Nothing here carries prompt text, tool input, or a transcript path.
type hookPayloadFields struct {
	sessionID     string
	model         string
	cwd           string
	toolName      string
	cursorVersion string
	timestamp     string
	mcpServer     string
	hookEventName string
}

// parseHookPayload reads only the fields the projection needs. A malformed
// payload yields zero values; the guardrail, not this code, is responsible for
// rejecting bad input.
//
// Fields are decoded one at a time rather than into a single struct. Agents
// change payload shapes between releases, and Claude Code already sends model
// as an object on some versions. A whole-struct decode fails on the first type
// it does not expect and discards every remaining field with it, including the
// hook_event_name that selects the record type - so one cosmetic upstream
// change would silently stop telemetry instead of dropping one attribute.
func parseHookPayload(payload []byte) hookPayloadFields {
	var out hookPayloadFields
	if len(payload) == 0 {
		return out
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(payload, &doc); err != nil {
		return out
	}
	out.sessionID = firstNonBlank(payloadString(doc, "session_id"), payloadString(doc, "conversation_id"))
	out.model = firstNonBlank(payloadModel(doc, "model"), payloadModel(doc, "model_name"))
	out.cwd = payloadString(doc, "cwd")
	out.toolName = firstNonBlank(payloadString(doc, "tool_name"), payloadString(doc, "toolName"))
	out.cursorVersion = payloadString(doc, "cursor_version")
	out.timestamp = payloadString(doc, "timestamp")
	out.mcpServer = payloadString(doc, "mcp_server_name")
	out.hookEventName = payloadString(doc, "hook_event_name")
	return out
}

// payloadString reads one string field. A value of any other type is reported
// absent, which keeps a single unexpected type local to its own field.
func payloadString(doc map[string]json.RawMessage, key string) string {
	raw, ok := doc[key]
	if !ok {
		return ""
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return ""
	}
	return strings.TrimSpace(value)
}

// payloadModel reads a model identifier that agents send either as a string or
// as an object describing the model. The stable id is preferred over the
// human-facing display name.
func payloadModel(doc map[string]json.RawMessage, key string) string {
	if value := payloadString(doc, key); value != "" {
		return value
	}
	raw, ok := doc[key]
	if !ok {
		return ""
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		return ""
	}
	return firstNonBlank(
		payloadString(object, "id"),
		payloadString(object, "model"),
		payloadString(object, "display_name"),
	)
}

// platformVersion reports a version only where the payload carries one that
// actually describes the agent.
//
// Cursor's cursor_version identifies the Cursor desktop application rather
// than the agent CLI, so it is the closest available evidence and is reported
// only for Cursor.
func (f hookPayloadFields) platformVersion(platform Platform) string {
	if platform == PlatformCursor {
		return f.cursorVersion
	}
	return ""
}

// mcpServerName resolves the MCP server behind a tool call when the tool name
// states it unambiguously.
//
// Claude Code and Codex namespace MCP tools as mcp__<server>__<tool>. Cursor
// instead supplies mcp_server_name on its MCP-specific events.
func (f hookPayloadFields) mcpServerName() string {
	if f.mcpServer != "" {
		return f.mcpServer
	}
	const prefix = "mcp__"
	name := f.toolName
	if !strings.HasPrefix(name, prefix) {
		return ""
	}
	rest := name[len(prefix):]
	idx := strings.Index(rest, "__")
	if idx <= 0 {
		return ""
	}
	return rest[:idx]
}

func firstNonBlank(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
