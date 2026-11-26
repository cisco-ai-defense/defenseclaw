// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
)

// TestGAP2223SandboxGuestOwnRootFollowsTheLinuxGateway: a Linux sandbox
// guest's /proc/self/root and /proc/thread-self/root are its own /. A Linux
// gateway reads its own root there and finds the guest's key file behind
// cd /proc/self/root && echo k >> sandbox/.ssh/<keys>; a macOS gateway (no
// /proc) gave the actor an alert, or an allow for the absolute spelling,
// where Linux blocks (rel-1-0-10:GAP-2223). Reached through that root,
// another process's root is unknown as on Linux (RV-2203c P2-1). Every row
// is the Linux gateway's answer, in the default and strict packs, on every
// gateway OS.
func TestGAP2223SandboxGuestOwnRootFollowsTheLinuxGateway(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires an unprivileged POSIX gateway")
	}
	kf := "authorized_" + "keys"
	k := "sandbox/.ssh/" + kf
	keys := []string{gap2203KeysRule}
	evalKeys := []string{"CMD-EVAL", gap2203KeysRule}
	evalOnly := []string{"CMD-EVAL"}
	ev := " && eval 'x=f; echo m > $x'"
	// pid1 rows go through process 1's entries (or a thread id a gateway
	// running as process 1 holds), which an unprivileged Linux gateway
	// cannot read; a gateway that can read them answers otherwise, so they
	// are skipped only there (as in TestGAP2203).
	rows := []struct {
		command, action string
		rules           []string
		pid1            bool
	}{
		{"cd /proc/self/root && echo k >> " + k, "block", keys, false},
		{"cd /proc/thread-self/root && echo k >> " + k, "block", keys, false},
		{"cd /proc/self/root/sandbox && echo k >> .ssh/" + kf, "block", keys, false},
		{"cd /proc/self/root && cd sandbox/.ssh && echo k >> " + kf, "block", keys, false},
		{"cd /proc/self && cd root && echo k >> " + k, "block", keys, false},
		{"cd /proc/self/root/proc/self/root && echo k >> " + k, "block", keys, false},
		{"cd -P /proc/self/root && echo k >> " + k, "block", keys, false},
		{"pushd /proc/self/root && echo k >> " + k, "block", keys, false},
		{"cd /proc/self/root && cp /tmp/k " + k, "block", keys, false},
		{"echo k >> /proc/self/root/" + k, "block", keys, false},
		{"echo k >> /proc/thread-self/root/" + k, "block", keys, false},
		{"echo k >> /proc/self/root/../" + k, "block", keys, false},
		{"echo k >> /proc/self/root/../../" + k, "block", keys, false},
		{"ln -s /proc/self/root/" + k + " l && echo k >> l", "block", keys, false},
		{"ln -s /proc/self/root/../" + k + " l && echo k >> l", "block", keys, false},
		{"echo k >> /proc/self/root/sandbox/.ssh/AUTHORIZED_KEYS", "allow", nil, false},
		{"cd /proc/self/root && eval 'x=" + k + "; echo k >> $x'", "block", evalKeys, false},
		{"cd /proc/self/root/proc/1/root" + ev, "block", evalKeys, true},
		{"cd /proc/thread-self/root/proc/1/root" + ev, "block", evalKeys, true},
		{"cd /proc/self/root && cd proc/1/root" + ev, "block", evalKeys, true},
		{"cd /proc/self/root/proc/1/cwd" + ev, "block", evalKeys, true},
		{"cd /proc/self/task/1/root && echo k >> " + k, "block", keys, true},
		{"cd /proc/self/root" + ev, "alert", evalOnly, false},
		{"cd /proc/self/root/proc/1" + ev, "alert", evalOnly, false},
		{"cd /proc/self/root && echo m > tmp/notes.txt", "allow", nil, false},
		{"cd /proc/self/root/sandbox && echo m > app/notes.txt", "allow", nil, false},
		{"echo m > /proc/self/root/sandbox/app/notes.txt", "allow", nil, false},
	}
	_, pid1Err := os.Readlink("/proc/1/root")
	pid1Readable := pid1Err == nil
	for _, pack := range []string{"default", "strict"} {
		t.Run(pack, func(t *testing.T) {
			api, actor, _, _ := gap0545API(t, "claudecode", pack)
			hook := func(ctx context.Context, body []byte) (string, []string) {
				req := httptest.NewRequest(http.MethodPost, "/api/v1/claudecode/hook", strings.NewReader(string(body)))
				req.Header.Set("Content-Type", "application/json")
				rec := httptest.NewRecorder()
				api.handleAgentHook("claudecode").ServeHTTP(rec, req.WithContext(ctx))
				var out struct {
					Action string   `json:"action"`
					Rules  []string `json:"rule_ids"`
				}
				if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &out) != nil {
					t.Fatalf("hook status=%d: %.400s", rec.Code, rec.Body.String())
				}
				slices.Sort(out.Rules)
				return out.Action, slices.Compact(out.Rules)
			}
			for _, row := range rows {
				if row.pid1 && pid1Readable {
					continue
				}
				body, _ := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "session_id": "gap2223",
					"cwd": sandboxauth.SandboxHome + "/app", "tool_name": "Bash", "tool_input": map[string]any{"command": row.command},
					"tool_use_id": "gap2223"})
				action, rules := hook(gap0545Actor(actor, "claudecode", "PreToolUse", body, nil), body)
				if action != row.action || !slices.Equal(rules, row.rules) {
					t.Errorf("%q: actor %s %v, want the Linux gateway's %s %v on every gateway OS", row.command, action, rules, row.action, row.rules)
				}
			}
		})
	}
}
