// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// rel-1-0-10:GAP-0437. An assignment whose $(( arithmetic has a syntax
// error made the recovering shell parse panic. On the hook route the
// handler's recovery answered a failed check; on the two OpenClaw routes
// (/api/v1/inspect/tool's worker goroutine and the exec.approval.requested
// goroutine) nothing recovered it and the gateway process exited. The parse
// is now contained (shellparse.ParseRecovering) and read as a bounded
// reading, and every route recovers an evaluator fault.
var gap0437Commands = []string{
	"h=$((t d",
	"echo first\nh=$((t d",
	"echo ssh-ed25519 AAAA k >> ~/.ssh/authorized_keys\nh=$((t d",
}

type gap0437Pack struct {
	name, pack string
	managed    bool
	strictTier bool
}

var gap0437Packs = []gap0437Pack{
	{name: "default", pack: "default"},
	{name: "strict", pack: "strict", strictTier: true},
	{name: "permissive", pack: "permissive"},
	{name: "managed", pack: "default", managed: true},
	{name: "managed-strict", pack: "strict", managed: true, strictTier: true},
}

func gap0437Server(t *testing.T, p gap0437Pack, connector string) *APIServer {
	t.Helper()
	store, logger := testStoreAndLogger(t)
	policies, err := filepath.Abs(filepath.Join("..", "..", "policies"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{}
	cfg.PolicyDir = policies
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = connector
	cfg.Guardrail.RulePack = p.pack
	cfg.Guardrail.DetectionStrategy = "regex_only"
	if p.managed {
		cfg.DeploymentMode = managed.DeploymentModeManagedEnterprise
		cfg.Enterprise.Profile = managed.ProfileStandalone
	}
	a := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, store, logger, cfg)
	prev := liveGeneration.Load()
	liveGeneration.Store(&Generation{Config: cfg})
	t.Cleanup(func() { liveGeneration.Store(prev) })
	return a
}

// gap0437Serve runs one request and fails the test if a panic escapes it.
func gap0437Serve(t *testing.T, h http.HandlerFunc, path string, body any) map[string]any {
	t.Helper()
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("%s: panic escaped the route: %v", path, r)
			}
		}()
		h.ServeHTTP(w, req)
	}()
	if w.Code != http.StatusOK {
		t.Fatalf("%s: status %d body %s", path, w.Code, w.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("%s: answer %q: %v", path, w.Body.String(), err)
	}
	return out
}

// gap0437AssertTier checks the unknown tier: block in the strict tier, an
// allowed alert (or stricter) otherwise; never a silent allow.
func gap0437AssertTier(t *testing.T, where string, p gap0437Pack, out map[string]any) {
	t.Helper()
	action, raw := out["action"], out["raw_action"]
	if p.strictTier {
		if action != "block" {
			t.Errorf("%s %s: action %v raw %v, want block (the strict unknown tier): %v", where, p.name, action, raw, out)
		}
		return
	}
	if raw != "alert" && raw != "block" {
		t.Errorf("%s %s: action %v raw %v, want the unknown tier's alert: %v", where, p.name, action, raw, out)
	}
}

// gap0437PowerShellExec reports whether the OpenClaw exec call is read in
// PowerShell (native Windows), where the POSIX arithmetic text is ordinary
// text: the call is judged on what PowerShell would do with it (the
// protected write blocks), not on the POSIX reading.
func gap0437PowerShellExec(command string, out map[string]any, t *testing.T, p gap0437Pack) bool {
	t.Helper()
	if runtime.GOOS != "windows" {
		return false
	}
	if strings.Contains(command, "authorized_keys") && out["action"] != "block" {
		t.Errorf("inspect/tool %s on Windows: the protected write is %v, want block: %v", p.name, out["action"], out)
	}
	return true
}

func gap0437NoFault(t *testing.T, before int64, where string) {
	t.Helper()
	if n := evaluatorFaults.Load() - before; n != 0 {
		t.Errorf("%s: %d evaluator fault(s) recovered; the parser must not panic on this input", where, n)
	}
}

func TestGAP0437ParserFaultHookRouteByPack(t *testing.T) {
	for _, p := range gap0437Packs {
		t.Run(p.name, func(t *testing.T) {
			a := gap0437Server(t, p, "claudecode")
			h := http.HandlerFunc(a.handleAgentHook("claudecode"))
			cwd := t.TempDir()
			for i, command := range gap0437Commands {
				before := evaluatorFaults.Load()
				out := gap0437Serve(t, h, "/api/v1/claude-code/hook", map[string]any{
					"hook_event_name": "PreToolUse", "session_id": "gap0437-" + p.name, "cwd": cwd,
					"tool_name": "Bash", "tool_use_id": "tu-gap0437-" + string(rune('a'+i)), "tool_input": map[string]any{"command": command},
				})
				gap0437AssertTier(t, "hook", p, out)
				gap0437NoFault(t, before, "hook "+p.name)
			}
		})
	}
}

func TestGAP0437ParserFaultInspectToolByPack(t *testing.T) {
	for _, p := range gap0437Packs {
		t.Run(p.name, func(t *testing.T) {
			a := gap0437Server(t, p, "openclaw")
			dir := t.TempDir()
			for _, command := range gap0437Commands {
				before := evaluatorFaults.Load()
				out := gap0437Serve(t, a.handleInspectTool, "/api/v1/inspect/tool", map[string]any{
					"tool": "exec", "connector": "openclaw", "args": map[string]any{"command": command, "workdir": dir},
				})
				if gap0437PowerShellExec(command, out, t, p) {
					continue
				}
				gap0437AssertTier(t, "inspect/tool", p, out)
				gap0437NoFault(t, before, "inspect/tool "+p.name)
			}
		})
	}
}

func TestGAP0437ParserFaultApprovalIsResolved(t *testing.T) {
	router, _, _ := bindEventRouterApprovalV8Runtime(t, false)
	received := make(chan receivedRequest, 8)
	server := startMockGW(t, rpcRecordingLoop(received))
	router.client = connectToMockGW(t, server)
	router.autoApprove = true
	for _, command := range gap0437Commands {
		before := evaluatorFaults.Load()
		payload, _ := json.Marshal(ApprovalRequestPayload{
			ID:      "approval-gap0437",
			Request: &ApprovalRequestRecord{Command: command, Cwd: t.TempDir()},
		})
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("approval %q: panic escaped: %v", command, r)
				}
			}()
			router.handleApprovalRequest(EventFrame{Type: "event", Event: "exec.approval.requested", Payload: payload})
		}()
		rpc := drainRPC(t, received)
		if rpc.Method != "exec.approval.resolve" {
			t.Fatalf("approval %q: RPC %q, want exec.approval.resolve", command, rpc.Method)
		}
		// The approval route has no alert: an evaluation-limit reading is
		// an enforceable CRITICAL finding, so the approval is denied. On
		// native Windows OpenClaw's exec is PowerShell, where the text is
		// no arithmetic: only the protected write is denied there.
		if runtime.GOOS == "windows" && !strings.Contains(command, "authorized_keys") {
			gap0437NoFault(t, before, "approval")
			continue
		}
		if !strings.Contains(string(rpc.Params), `"decision":"deny"`) {
			t.Errorf("approval %q: resolve %s, want a denial", command, rpc.Params)
		}
		gap0437NoFault(t, before, "approval")
	}
}

// A panic anywhere in the evaluation (here: injected at the start of
// dispatchTrustedAction) is the pack's unknown tier on every route, is
// counted and logged, and never leaves the route.
func TestGAP0437EvaluatorPanicIsUnknownTierOnEveryRoute(t *testing.T) {
	trustedActionFaultHook = func(trustedActionRequest) { panic("gap0437 injected evaluator fault") }
	t.Cleanup(func() { trustedActionFaultHook = nil })
	for _, p := range gap0437Packs {
		t.Run(p.name, func(t *testing.T) {
			a := gap0437Server(t, p, "claudecode")
			before := evaluatorFaults.Load()
			hook := gap0437Serve(t, a.handleAgentHook("claudecode"), "/api/v1/claude-code/hook", map[string]any{
				"hook_event_name": "PreToolUse", "session_id": "gap0437-fault-" + p.name, "cwd": t.TempDir(),
				"tool_name": "Bash", "tool_use_id": "tu-gap0437-fault", "tool_input": map[string]any{"command": "ls"},
			})
			gap0437AssertTier(t, "hook", p, hook)
			a = gap0437Server(t, p, "openclaw")
			inspect := gap0437Serve(t, a.handleInspectTool, "/api/v1/inspect/tool", map[string]any{
				"tool": "exec", "connector": "openclaw", "args": map[string]any{"command": "ls", "workdir": t.TempDir()},
			})
			gap0437AssertTier(t, "inspect/tool", p, inspect)
			if evaluatorFaults.Load() == before {
				t.Errorf("%s: the injected faults were not counted", p.name)
			}
		})
	}
	t.Run("dispatch", func(t *testing.T) {
		findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
			Connector: "claudecode", EnforcementCapable: true,
		})
		if len(findings) != 1 || findings[0].RuleID != "ACTION-COMPOUND-LIMIT" ||
			!strings.Contains(findings[0].Evidence, "bounded_truncated cap=nodes") {
			t.Fatalf("dispatch fault findings %+v, want the bounded evaluation-limit finding", findings)
		}
	})
	t.Run("approval", func(t *testing.T) {
		router, _, _ := bindEventRouterApprovalV8Runtime(t, false)
		received := make(chan receivedRequest, 4)
		server := startMockGW(t, rpcRecordingLoop(received))
		router.client = connectToMockGW(t, server)
		router.autoApprove = true
		payload, _ := json.Marshal(ApprovalRequestPayload{ID: "approval-fault", Request: &ApprovalRequestRecord{Command: "ls", Cwd: t.TempDir()}})
		router.handleApprovalRequest(EventFrame{Type: "event", Event: "exec.approval.requested", Payload: payload})
		if rpc := drainRPC(t, received); !strings.Contains(string(rpc.Params), `"decision":"deny"`) {
			t.Errorf("approval after an evaluator fault: %s, want a denial", rpc.Params)
		}
	})
	t.Run("event tool_call", func(t *testing.T) {
		router, _, _ := bindEventRouterApprovalV8Runtime(t, false)
		payload, _ := json.Marshal(map[string]any{"tool": "exec", "id": "tc-fault", "args": map[string]any{"command": "ls"}})
		router.Route(EventFrame{Type: "event", Event: "tool_call", Payload: payload})
	})
}

// The goroutine recoveries keep the process running and answer the caller
// when the failure is outside the evaluation.
func TestGAP0437GoroutineFaultIsAnswered(t *testing.T) {
	answered := make(chan bool, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer recoverGatewayGoroutine("test", func() { answered <- true })
		panic("gap0437 goroutine fault")
	}()
	<-done
	if !<-answered {
		t.Fatal("no failed-check answer")
	}
	a := gap0437Server(t, gap0437Pack{name: "default", pack: "default"}, "openclaw")
	a.inspectToolWorkerDone = func() { panic("gap0437 worker fault") }
	out := gap0437Serve(t, a.handleInspectTool, "/api/v1/inspect/tool", map[string]any{
		"tool": "exec", "connector": "openclaw", "args": map[string]any{"command": "ls", "workdir": t.TempDir()},
	})
	if out["action"] == nil {
		t.Fatalf("inspect/tool after a worker fault: %v", out)
	}
}
