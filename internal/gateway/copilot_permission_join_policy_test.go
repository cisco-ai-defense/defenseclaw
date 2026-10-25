// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
)

// copilotJoinPost sends one native Copilot CLI hook body and returns the
// verdict action and body.
func copilotJoinPost(t *testing.T, api *APIServer, event, body string) (string, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/copilot/hook", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-DefenseClaw-Copilot-Event", event)
	w := httptest.NewRecorder()
	api.handleAgentHook("copilot").ServeHTTP(w, req)
	var verdict struct {
		Action string `json:"action"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &verdict); err != nil {
		return "rejected", w.Body.String()
	}
	return verdict.Action, w.Body.String()
}

func copilotJoinQuote(t *testing.T, value string) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

// copilotJoinPreToolUse is an audited benign apply_patch preToolUse.
func copilotJoinPreToolUse(t *testing.T, session, project string) string {
	patch := copilotJoinQuote(t, "*** Begin Patch\n*** Add File: README.md\n+ordinary project text\n*** End Patch\n")
	return `{"sessionId":"` + session + `","cwd":` + copilotJoinQuote(t, project) +
		`,"toolCalls":[{"id":"call_join","name":"apply_patch","args":` + patch + `}]}`
}

func copilotJoinPermission(t *testing.T, session, project string) string {
	return `{"hookName":"permissionRequest","sessionId":"` + session + `","cwd":` + copilotJoinQuote(t, project) +
		`,"toolName":"edit","toolInput":{}}`
}

// copilotJoinManagedPost sends one native Copilot CLI hook body to a
// standalone managed gateway the way its hook does, and acknowledges the
// proposed answer (the delivery receipt), so the answer is the one the
// agent got. It returns the proposed answer line.
func copilotJoinManagedPost(t *testing.T, f managedHookAuditFixture, event, body string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	reader, writer := io.Pipe()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, f.server.URL+"/api/v1/copilot/hook", reader)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set(hookexec.HookDeliveryReceiptHeader, "1")
	request.Header.Set(hookexec.HookDeliveryPayloadBytesHeader, strconv.Itoa(len(body)))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-DefenseClaw-Copilot-Event", event)
	responseCh := make(chan *http.Response, 1)
	errorCh := make(chan error, 1)
	go func() {
		response, requestErr := f.server.Client().Do(request)
		if requestErr != nil {
			errorCh <- requestErr
			return
		}
		responseCh <- response
	}()
	if _, err := io.WriteString(writer, body); err != nil {
		t.Fatal(err)
	}
	var response *http.Response
	select {
	case response = <-responseCh:
	case err := <-errorCh:
		t.Fatalf("%s: gateway gave no answer: %v", event, err)
	case <-ctx.Done():
		t.Fatalf("%s: gateway gave no answer before the deadline", event)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("%s: status %d", event, response.StatusCode)
	}
	line, err := bufio.NewReader(response.Body).ReadString('\n')
	if err != nil {
		t.Fatalf("%s: proposed answer %q: %v", event, line, err)
	}
	if _, err := io.WriteString(writer, hookexec.HookDeliveryReceiptAck); err != nil {
		t.Fatal(err)
	}
	_ = writer.Close()
	_, _ = io.Copy(io.Discard, response.Body)
	return line
}

// The require-sandbox floor is read live on every host hook of a standalone
// managed gateway. A permission callback that reuses an earlier preToolUse
// allow must still be refused once the caller's floor requires Copilot in a
// sandbox (T12b round d review, loop round 2).
func TestNativeCopilotPermissionJoinRunsTheLiveSandboxGate(t *testing.T) {
	useSandboxAvailability(t, sandboxDevicesUsable)
	project := requireSandboxProject(t)
	f := newManagedHookAuditFixtureFor(t, "copilot", nil)
	cfg := f.api.liveBaseConfig(t.Context())
	cfg.OpenShell.Enabled = true
	cfg.OpenShell.Admin.RequestAccess = "it-security@example.com"

	// Control: with no floor the empty callback reuses the allow (so the
	// refusal below is the sandbox gate, not a missed join).
	if line := copilotJoinManagedPost(t, f, "preToolUse", copilotJoinPreToolUse(t, "control", project)); !strings.Contains(line, `"action":"allow"`) {
		t.Fatalf("control preToolUse: %s", line)
	}
	if line := copilotJoinManagedPost(t, f, "permissionRequest", copilotJoinPermission(t, "control", project)); !strings.Contains(line, `"action":"allow"`) {
		t.Fatalf("control permission did not reuse the allow: %s", line)
	}

	if line := copilotJoinManagedPost(t, f, "preToolUse", copilotJoinPreToolUse(t, "floor", project)); !strings.Contains(line, `"action":"allow"`) {
		t.Fatalf("preToolUse: %s", line)
	}
	cfg.OpenShell.Admin.RequiredFor = []string{"copilot"}
	line := copilotJoinManagedPost(t, f, "permissionRequest", copilotJoinPermission(t, "floor", project))
	if strings.Contains(line, `"action":"allow"`) || !strings.Contains(line, "sandbox") {
		t.Fatalf("permission callback skipped the newly required sandbox gate: %s", line)
	}
	if got := requireSandboxAuditOutcome(t, f.store); got != requireSandboxRefused && got != requireSandboxUnavailable {
		t.Fatalf("audit require_sandbox = %q, want a refusal: %s", got, line)
	}
}

// A decision made under one policy generation is stale under the next:
// a config, bundle or asset swap between the preToolUse and its permission
// callback sends the callback to its own gate.
func TestNativeCopilotPermissionJoinDropsAllowsOfAnotherPolicy(t *testing.T) {
	project := t.TempDir()
	store, logger := testStoreAndLogger(t)
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "copilot"
	var current atomic.Pointer[Generation]
	current.Store(&Generation{Config: cfg, Digest: "sha256:first"})
	api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth(), store: store, logger: logger,
		generationSource: func() *Generation { return current.Load() }}

	if action, body := copilotJoinPost(t, api, "preToolUse", copilotJoinPreToolUse(t, "same", project)); action != "allow" {
		t.Fatalf("control preToolUse action=%s: %s", action, body)
	}
	if action, body := copilotJoinPost(t, api, "permissionRequest", copilotJoinPermission(t, "same", project)); action != "allow" {
		t.Fatalf("control permission under the same policy action=%s: %s", action, body)
	}

	if action, body := copilotJoinPost(t, api, "preToolUse", copilotJoinPreToolUse(t, "swapped", project)); action != "allow" {
		t.Fatalf("preToolUse action=%s: %s", action, body)
	}
	current.Store(&Generation{N: 0, Config: cfg, Digest: "sha256:second"})
	if action, body := copilotJoinPost(t, api, "permissionRequest", copilotJoinPermission(t, "swapped", project)); action == "allow" {
		t.Fatalf("permission callback reused an allow of the previous policy: %s", body)
	}
}

func TestCopilotPermissionPolicyNamesGenerationAndProfile(t *testing.T) {
	first := &Generation{N: 4, Digest: "sha256:a"}
	api := &APIServer{generationSource: func() *Generation { return first }}
	ctx := context.Background()
	base := api.copilotPermissionPolicy(ctx)
	if base != api.copilotPermissionPolicy(ctx) {
		t.Fatal("the policy stamp of one generation is not stable")
	}
	for name, other := range map[string]context.Context{
		"generation counter": withPinnedGeneration(ctx, &Generation{N: 5, Digest: "sha256:a"}),
		"generation digest":  withPinnedGeneration(ctx, &Generation{N: 4, Digest: "sha256:b"}),
		"profile": context.WithValue(ctx, resolvedGuardrailProfileKey{},
			&resolvedGuardrailProfile{decision: profileDecision{Name: "contractors", Digest: "sha256:p"}}),
		"refused profile": context.WithValue(ctx, resolvedGuardrailProfileKey{},
			&resolvedGuardrailProfile{decision: profileDecision{Refused: "group"}}),
	} {
		if api.copilotPermissionPolicy(other) == base {
			t.Errorf("%s: a different policy has the same stamp", name)
		}
	}
	if (&APIServer{}).copilotPermissionPolicy(ctx) == base {
		t.Error("no generation has the stamp of a published one")
	}
}

func TestCopilotPermissionJoinRefusesShapeUnparsedAndStalePolicy(t *testing.T) {
	ctx := context.Background()
	pre := agentHookRequest{ConnectorName: "copilot", HookEventName: "preToolUse", SessionID: "native",
		CWD: "/tmp/native", ToolName: "apply_patch"}
	permission := func() agentHookRequest {
		return agentHookRequest{ConnectorName: "copilot", HookEventName: "permissionRequest",
			SessionID: "native", CWD: "/tmp/native", ToolName: "edit", ToolCallUnparsed: true,
			Payload: map[string]any{"hookName": "permissionRequest", "toolName": "edit", "toolInput": map[string]any{}}}
	}
	raw := []byte(`{"hookName":"permissionRequest","toolName":"edit","toolInput":{}}`)
	allow := agentHookResponse{Action: "allow"}
	for _, tc := range []struct {
		name   string
		mutate func(*agentHookRequest) string
		want   bool
	}{
		{"argumentless", func(*agentHookRequest) string { return "p1" }, true},
		{"shape unparsed", func(req *agentHookRequest) string { req.toolCallShapeUnparsed = true; return "p1" }, false},
		{"another policy", func(*agentHookRequest) string { return "p2" }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var join copilotPermissionJoin
			join.record(ctx, pre, allow, "p1")
			req := permission()
			policy := tc.mutate(&req)
			if _, ok := join.match(ctx, req, connector.HookProfile{}, raw, policy); ok != tc.want {
				t.Fatalf("match=%v want %v", ok, tc.want)
			}
			// Either way the callback consumed the one prior decision.
			if _, ok := join.match(ctx, permission(), connector.HookProfile{}, raw, "p1"); ok {
				t.Fatal("a second callback reused the consumed decision")
			}
		})
	}
}
