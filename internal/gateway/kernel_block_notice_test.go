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
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/sensor"
	"github.com/defenseclaw/defenseclaw/internal/sensor/plane"
)

type fakeKernelBlocks struct {
	blocks []sensor.KernelBlock
	roots  map[int]int
}

func (f fakeKernelBlocks) KernelBlocks(since time.Time) []sensor.KernelBlock {
	var out []sensor.KernelBlock
	for _, block := range f.blocks {
		if !block.At.Before(since) {
			out = append(out, block)
		}
	}
	return out
}

func (f fakeKernelBlocks) SessionRootOf(pid int) (int, bool) {
	root, ok := f.roots[pid]
	return root, ok
}

var noticeNow = time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)

func sshBlock(id string) sensor.KernelBlock {
	return sensor.KernelBlock{
		ID: id, At: noticeNow.Add(-5 * time.Second), Owner: plane.PolicyOwnerDefenseClaw,
		Control: "kernel.ssh_private_key_read", RuleID: "PATH-SSH-KEY", Policy: "defenseclaw-controls-0a1b2c3d",
		Process: "python3", Target: "/home/dev/.ssh/id_ed25519", UID: runtimeIntp(1001),
		RootPID: 1300, SessionRootPID: 1300, Connector: "claudecode", SessionID: "sess-1", ToolInvocationID: "tool-1",
	}
}

func postToolRequest(connectorName, event string) (agentHookRequest, []byte, map[string]interface{}) {
	body := `{"hook_event_name":"` + event + `","session_id":"sess-1","tool_name":"Bash","tool_input":{"command":"cat x"},` +
		`"tool_use_id":"tool-1","tool_response":{"stdout":"","stderr":"Operation not permitted"},"cwd":"/home/dev"}`
	var payload map[string]interface{}
	_ = json.Unmarshal([]byte(body), &payload)
	return agentHookRequest{
		ConnectorName: connectorName, HookEventName: event, SessionID: "sess-1", ToolInvocationID: "tool-1", ToolName: "Bash",
		Payload: payload,
	}, []byte(body), payload
}

// contextField finds the harness field the notice was rendered into.
func contextField(value interface{}, needle string) string {
	switch v := value.(type) {
	case map[string]interface{}:
		for key, child := range v {
			if text, ok := child.(string); ok && strings.Contains(text, needle) {
				return key
			}
			if found := contextField(child, needle); found != "" {
				return found
			}
		}
	}
	return ""
}

func withHomes(t *testing.T) {
	t.Helper()
	saved := kernelUserHome
	kernelUserHome = func(*int, string) string { return "/home/dev" }
	t.Cleanup(func() { kernelUserHome = saved })
}

// TestKernelBlockNoticePerConnector: each harness whose post-tool hook has a
// context field the model reads gets the notice there, once.
func TestKernelBlockNoticePerConnector(t *testing.T) {
	withHomes(t)
	api := &APIServer{}
	for connectorName, events := range postToolContextEvents {
		for _, event := range events {
			hookEvent := map[string]string{"posttooluse": "PostToolUse", "posttoolusefailure": "PostToolUseFailure"}[event]
			req, raw, payload := postToolRequest(connectorName, hookEvent)
			profile := api.hookProfileForConnector(connectorName)
			source := fakeKernelBlocks{blocks: []sensor.KernelBlock{sshBlock("kblock-1")}}
			ledger := newKernelNoticeLedger()
			resp := addKernelBlockNotice(context.Background(), profile, connectorName, req, raw, payload,
				agentHookResponse{Action: "allow", RawAction: "allow"}, source, 4242, 1001, ledger, noticeNow)
			want := "DefenseClaw blocked `python3` from reading your SSH private key (~/.ssh/id_ed25519) under your organization's policy " +
				`(PATH-SSH-KEY, a kernel control). The tool saw "Operation not permitted". Do not retry it. Contact your administrator if you need it allowed.`
			if resp.AdditionalContext != want {
				t.Fatalf("%s %s: context %q", connectorName, hookEvent, resp.AdditionalContext)
			}
			if field := contextField(resp.HookOutput, "PATH-SSH-KEY"); field != "additionalContext" && field != "additional_context" {
				t.Fatalf("%s %s: rendered into %q: %v", connectorName, hookEvent, field, resp.HookOutput)
			}
			if len(resp.KernelBlocksTold) != 1 || resp.KernelBlocksTold[0] != "kblock-1" {
				t.Fatalf("%s: told %v", connectorName, resp.KernelBlocksTold)
			}
			again := addKernelBlockNotice(context.Background(), profile, connectorName, req, raw, payload,
				agentHookResponse{Action: "allow", RawAction: "allow"}, source, 4242, 1001, ledger, noticeNow)
			if again.AdditionalContext != "" || len(again.KernelBlocksTold) != 0 {
				t.Fatalf("%s: told twice: %q", connectorName, again.AdditionalContext)
			}
		}
	}
}

// TestKernelBlockNoticeOnlyTellsTheSessionsDenials: the session's hook join
// or its agent root decides; a pre-tool hook, a harness without a context
// field, a block or ask answer and an old denial tell nothing, and a block
// answer leaves the denial for the next post-tool hook.
func TestKernelBlockNoticeOnlyTellsTheSessionsDenials(t *testing.T) {
	withHomes(t)
	api := &APIServer{}
	profile := api.hookProfileForConnector("claudecode")
	req, raw, payload := postToolRequest("claudecode", "PostToolUse")
	other := sshBlock("kblock-other")
	other.SessionID, other.RootPID, other.SessionRootPID = "sess-2", 2300, 2300
	old := sshBlock("kblock-old")
	old.At = noticeNow.Add(-3 * time.Minute)
	byRoot := sshBlock("kblock-root")
	byRoot.SessionID, byRoot.ToolInvocationID = "", ""
	source := fakeKernelBlocks{blocks: []sensor.KernelBlock{other, old, byRoot}, roots: map[int]int{4242: 1300}}
	ledger := newKernelNoticeLedger()
	allow := agentHookResponse{Action: "allow", RawAction: "allow"}

	for _, tc := range []struct {
		name      string
		connector string
		event     string
		resp      agentHookResponse
	}{
		{"pre-tool", "claudecode", "PreToolUse", allow},
		{"no context field", "hermes", "post_tool_call", allow},
		{"block answer", "claudecode", "PostToolUse", agentHookResponse{Action: "block", RawAction: "block", Reason: "kept"}},
		{"ask answer", "claudecode", "PostToolUse", agentHookResponse{Action: "confirm", RawAction: "confirm"}},
	} {
		r := req
		r.ConnectorName, r.HookEventName = tc.connector, tc.event
		got := addKernelBlockNotice(context.Background(), profile, tc.connector, r, raw, payload, tc.resp, source, 4242, 1001, ledger, noticeNow)
		if got.AdditionalContext != tc.resp.AdditionalContext || got.Reason != tc.resp.Reason || len(got.KernelBlocksTold) != 0 {
			t.Fatalf("%s: changed %+v", tc.name, got)
		}
	}
	got := addKernelBlockNotice(context.Background(), profile, "claudecode", req, raw, payload, allow, source, 4242, 1001, ledger, noticeNow)
	if len(got.KernelBlocksTold) != 1 || got.KernelBlocksTold[0] != "kblock-root" {
		t.Fatalf("told %v: %q", got.KernelBlocksTold, got.AdditionalContext)
	}
	// Without the peer's root, only the session's own hook join counts.
	source.roots = nil
	source.blocks = append(source.blocks, sshBlock("kblock-session"))
	got = addKernelBlockNotice(context.Background(), profile, "claudecode", req, raw, payload, allow, source, 4242, 1001, ledger, noticeNow)
	if len(got.KernelBlocksTold) != 1 || got.KernelBlocksTold[0] != "kblock-session" {
		t.Fatalf("told %v", got.KernelBlocksTold)
	}
}

// TestKernelBlockNoticeNeverCrossesUsers: the session id in a hook payload is
// the caller's word. Another user's agent that sends this user's session id
// learns nothing of this user's denials, nor of a denial whose user is not
// known, even with the same agent root.
func TestKernelBlockNoticeNeverCrossesUsers(t *testing.T) {
	withHomes(t)
	api := &APIServer{}
	profile := api.hookProfileForConnector("claudecode")
	req, raw, payload := postToolRequest("claudecode", "PostToolUse")
	unknown := sshBlock("kblock-unknown-user")
	unknown.UID = nil
	source := fakeKernelBlocks{blocks: []sensor.KernelBlock{sshBlock("kblock-alice"), unknown}, roots: map[int]int{4242: 1300}}
	allow := agentHookResponse{Action: "allow", RawAction: "allow"}
	ledger := newKernelNoticeLedger()
	if got := addKernelBlockNotice(context.Background(), profile, "claudecode", req, raw, payload, allow, source, 4242, 1002, ledger, noticeNow); got.AdditionalContext != "" ||
		len(got.KernelBlocksTold) != 0 {
		t.Fatalf("another user was told %v: %q", got.KernelBlocksTold, got.AdditionalContext)
	}
	got := addKernelBlockNotice(context.Background(), profile, "claudecode", req, raw, payload, allow, source, 4242, 1001, ledger, noticeNow)
	if len(got.KernelBlocksTold) != 1 || got.KernelBlocksTold[0] != "kblock-alice" {
		t.Fatalf("the user's own denial: told %v", got.KernelBlocksTold)
	}
}

func TestKernelBlockNoticeText(t *testing.T) {
	withHomes(t)
	customer := sensor.KernelBlock{ID: "c", Owner: plane.PolicyOwnerCustomer, Policy: "file-sensitive", Function: "security_file_open",
		Action: "override", Process: "cat", Target: "/etc/shadow"}
	persistence := sensor.KernelBlock{ID: "p", Owner: plane.PolicyOwnerDefenseClaw, Control: "kernel.persistence_write",
		RuleID: "persistence.shell_profile_write", Process: "sh", Target: "/home/dev/.bashrc", ToolInvocationID: "tool-0"}
	text := kernelBlockNoticeText([]sensor.KernelBlock{customer, persistence, sshBlock("1"), sshBlock("2"), sshBlock("3")}, "tool-1")
	lines := strings.Split(text, "\n")
	if len(lines) != 4 {
		t.Fatalf("%d lines: %s", len(lines), text)
	}
	// A customer policy's Override may return any error: the notice names no
	// errno. A DefenseClaw control always returns EPERM.
	if lines[0] != "Your organization's Tetragon policy `file-sensitive` blocked `cat` (security_file_open). "+
		"The call failed. Do not retry it. Contact your administrator if you need it allowed." {
		t.Fatalf("customer line %q", lines[0])
	}
	if !strings.Contains(lines[1], `The tool saw "Operation not permitted". Do not retry it.`) {
		t.Fatalf("persistence line %q", lines[1])
	}
	killed := customer
	killed.Action = "sigkill"
	if got := kernelBlockSentence(killed, false); !strings.Contains(got, "blocked `cat` (security_file_open). The process was stopped. Do not retry it.") {
		t.Fatalf("sigkill line %q", got)
	}
	if !strings.HasPrefix(lines[1], "In an earlier tool call, DefenseClaw blocked `sh` from changing your shell startup or autostart file (~/.bashrc)") ||
		!strings.Contains(lines[1], "(persistence.shell_profile_write, a kernel control)") {
		t.Fatalf("persistence line %q", lines[1])
	}
	if lines[3] != "And 2 more calls of this agent were blocked the same way." {
		t.Fatalf("count line %q", lines[3])
	}
	if got := kernelBlockSentence(customer, true); !strings.HasPrefix(got, "In an earlier tool call, your organization's Tetragon policy") {
		t.Fatalf("earlier customer %q", got)
	}
}

// TestKernelBlockNoticeNeverOnAnUnmanagedHost: no managed hook peer, no
// notice, and the runtime planes are not even asked.
func TestKernelBlockNoticeNeverOnAnUnmanagedHost(t *testing.T) {
	t.Parallel()
	api := &APIServer{}
	req, raw, payload := postToolRequest("claudecode", "PostToolUse")
	resp := agentHookResponse{Action: "allow", RawAction: "allow", AdditionalContext: "kept"}
	got := api.safeAddKernelBlockNotice(context.Background(), api.hookProfileForConnector("claudecode"), "claudecode", req, raw, payload, resp)
	if got.AdditionalContext != "kept" || len(got.KernelBlocksTold) != 0 {
		t.Fatalf("unmanaged host: %+v", got)
	}
}
