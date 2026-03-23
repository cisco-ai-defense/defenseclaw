package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/enforce"
)

// EventRouter dispatches gateway events to the appropriate handlers and logs
// everything to the audit store.
type EventRouter struct {
	client *Client
	store  *audit.Store
	logger *audit.Logger
	policy *enforce.PolicyEngine

	autoApprove bool
}

// NewEventRouter creates a router that handles gateway events for the sidecar.
func NewEventRouter(client *Client, store *audit.Store, logger *audit.Logger, autoApprove bool) *EventRouter {
	return &EventRouter{
		client:      client,
		store:       store,
		logger:      logger,
		policy:      enforce.NewPolicyEngine(store),
		autoApprove: autoApprove,
	}
}

// Route dispatches a single event frame to the correct handler.
func (r *EventRouter) Route(evt EventFrame) {
	switch evt.Event {
	case "tool_call":
		r.handleToolCall(evt)
	case "tool_result":
		r.handleToolResult(evt)
	case "exec.approval.requested":
		r.handleApprovalRequest(evt)
	case "tick":
		// keepalive, no action needed
	default:
		// log unhandled events at debug level in the future
	}
}

func (r *EventRouter) handleToolCall(evt EventFrame) {
	var payload ToolCallPayload
	if err := json.Unmarshal(evt.Payload, &payload); err != nil {
		fmt.Fprintf(os.Stderr, "[sidecar] parse tool_call: %v\n", err)
		return
	}

	_ = r.logger.LogAction("gateway-tool-call", payload.Tool,
		fmt.Sprintf("status=%s args=%s", payload.Status, truncate(string(payload.Args), 200)))

	if r.isDangerousTool(payload.Tool, payload.Args) {
		_ = r.logger.LogAction("gateway-tool-call-flagged", payload.Tool,
			fmt.Sprintf("reason=dangerous-pattern args=%s", truncate(string(payload.Args), 200)))
		fmt.Fprintf(os.Stderr, "[sidecar] FLAGGED tool call: %s\n", payload.Tool)
	}
}

func (r *EventRouter) handleToolResult(evt EventFrame) {
	var payload ToolResultPayload
	if err := json.Unmarshal(evt.Payload, &payload); err != nil {
		fmt.Fprintf(os.Stderr, "[sidecar] parse tool_result: %v\n", err)
		return
	}

	exitCode := 0
	if payload.ExitCode != nil {
		exitCode = *payload.ExitCode
	}

	_ = r.logger.LogAction("gateway-tool-result", payload.Tool,
		fmt.Sprintf("exit_code=%d output_len=%d", exitCode, len(payload.Output)))
}

func (r *EventRouter) handleApprovalRequest(evt EventFrame) {
	var payload ApprovalRequestPayload
	if err := json.Unmarshal(evt.Payload, &payload); err != nil {
		fmt.Fprintf(os.Stderr, "[sidecar] parse exec.approval.requested: %v\n", err)
		return
	}

	rawCmd := ""
	if payload.SystemRunPlan != nil {
		rawCmd = payload.SystemRunPlan.RawCommand
	}

	_ = r.logger.LogAction("gateway-approval-requested", payload.ID,
		fmt.Sprintf("command=%s", truncate(rawCmd, 300)))

	if r.isCommandDangerous(rawCmd) {
		_ = r.logger.LogAction("gateway-approval-denied", payload.ID,
			fmt.Sprintf("reason=dangerous-command command=%s", truncate(rawCmd, 200)))
		fmt.Fprintf(os.Stderr, "[sidecar] DENIED exec approval: %s\n", truncate(rawCmd, 100))

		ctx, cancel := r.approvalCtx()
		defer cancel()
		if err := r.client.ResolveApproval(ctx, payload.ID, false,
			"defenseclaw: command matched dangerous pattern"); err != nil {
			fmt.Fprintf(os.Stderr, "[sidecar] resolve approval error: %v\n", err)
		}
		return
	}

	if r.autoApprove {
		_ = r.logger.LogAction("gateway-approval-granted", payload.ID,
			fmt.Sprintf("reason=auto-approve command=%s", truncate(rawCmd, 200)))
		fmt.Fprintf(os.Stderr, "[sidecar] AUTO-APPROVED exec: %s\n", truncate(rawCmd, 100))

		ctx, cancel := r.approvalCtx()
		defer cancel()
		if err := r.client.ResolveApproval(ctx, payload.ID, true,
			"defenseclaw: auto-approved safe command"); err != nil {
			fmt.Fprintf(os.Stderr, "[sidecar] resolve approval error: %v\n", err)
		}
	}
}

// approvalCtx returns a context with a timeout for approval resolution RPCs.
// The caller is responsible for calling the returned cancel function.
func (r *EventRouter) approvalCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 10*time.Second)
}

var dangerousPatterns = []string{
	"curl",
	"wget",
	"nc ",
	"ncat",
	"netcat",
	"/dev/tcp",
	"base64 -d",
	"base64 --decode",
	"eval ",
	"bash -c",
	"sh -c",
	"python -c",
	"perl -e",
	"ruby -e",
	"rm -rf /",
	"dd if=",
	"mkfs",
	"chmod 777",
	"> /etc/",
	">> /etc/",
	"passwd",
	"shadow",
	"sudoers",
}

func (r *EventRouter) isDangerousTool(tool string, args json.RawMessage) bool {
	if tool != "shell" && tool != "system.run" && tool != "exec" {
		return false
	}

	argsStr := strings.ToLower(string(args))
	for _, pattern := range dangerousPatterns {
		if strings.Contains(argsStr, pattern) {
			return true
		}
	}
	return false
}

func (r *EventRouter) isCommandDangerous(rawCmd string) bool {
	lower := strings.ToLower(rawCmd)
	for _, pattern := range dangerousPatterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
