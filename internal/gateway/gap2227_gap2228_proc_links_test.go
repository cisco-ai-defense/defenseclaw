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
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
)

// gap2227Hook judges one Claude Code Bash call in cwd for ctx.
func gap2227Hook(t *testing.T, api *APIServer, ctx context.Context, cwd, command string, actor bool) (string, []string) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "session_id": "gap2227",
		"cwd": cwd, "tool_name": "Bash", "tool_input": map[string]any{"command": command}, "tool_use_id": "gap2227"})
	if actor {
		ctx = gap0545Actor(ctx, "claudecode", "PreToolUse", body, nil)
	}
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

// TestGAP2227WriteBelowAnotherProcessLinkIsUnknown: a key file name below
// another process's root, cwd, exe or descriptor link is resolved in that
// process's tree. The copy-mode actor's processes are not the gateway's, so
// on every gateway OS such a write is unknown and blocks, as the
// /proc/<pid>/cwd spelling already did; a Linux laptop whose gateway cannot
// read /proc/1/root does the same, while a macOS laptop (no /proc) keeps its
// answer. A write to the link itself, other names below it and /proc reads
// keep theirs (rel-1-0-10:GAP-2227).
func TestGAP2227WriteBelowAnotherProcessLinkIsUnknown(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires an unprivileged POSIX gateway")
	}
	kf := "authorized_" + "keys"
	keys := []string{gap2203KeysRule}
	actorRows := []struct {
		command, action string
		rules           []string
	}{
		{"echo k >> /proc/1/root/sandbox/.ssh/" + kf, "block", keys},
		{"echo k >> /proc/1/task/1/root/sandbox/.ssh/" + kf, "block", keys},
		{"echo k >> /proc/1/fd/3/.ssh/" + kf, "block", keys},
		{"echo k >> /proc/self/root/proc/1/root/sandbox/.ssh/" + kf, "block", keys},
		{"cd /proc/1/root/sandbox && echo k >> .ssh/" + kf, "block", keys},
		{"cd /proc/1/root && echo k >> sandbox/.ssh/" + kf, "block", keys},
		{"echo k >> /proc/1/cwd/" + kf, "block", keys},
		{"echo m > /proc/1/root/tmp/notes.txt", "allow", nil},
		{"cd /proc/1/root && echo m > notes.txt", "allow", nil},
		{"echo m > /proc/1/fd/1", "allow", nil},
		{"echo 1000 > /proc/1/oom_score_adj", "allow", nil},
		{"cat /proc/1/root/etc/hostname > " + sandboxauth.SandboxHome + "/app/h.txt", "allow", nil},
		{"cat /proc/1/status", "allow", nil},
	}
	_, pid1Err := os.Readlink("/proc/1/root")
	for _, pack := range []string{"default", "strict"} {
		t.Run(pack, func(t *testing.T) {
			api, actor, home, app := gap0545API(t, "claudecode", pack)
			for _, row := range actorRows {
				action, rules := gap2227Hook(t, api, actor, sandboxauth.SandboxHome+"/app", row.command, true)
				if action != row.action || !slices.Equal(rules, row.rules) {
					t.Errorf("actor %q: %s %v, want %s %v on every gateway OS", row.command, action, rules, row.action, row.rules)
				}
			}
			// The laptop is this host: a Linux gateway that cannot read
			// process 1's root cannot show where the write lands; a macOS
			// host has no /proc to write through.
			if runtime.GOOS == "linux" && pid1Err == nil {
				t.Log("gateway reads /proc/1/root: laptop rows skipped")
				return
			}
			want, wantRules := "allow", []string(nil)
			if runtime.GOOS == "linux" {
				want, wantRules = "block", keys
			}
			for _, row := range []struct {
				command, action string
				rules           []string
			}{
				{"echo k >> /proc/1/root" + home + "/.ssh/" + kf, want, wantRules},
				{"echo k >> /proc/1/task/1/root" + home + "/.ssh/" + kf, want, wantRules},
				{"echo m > /proc/1/root" + home + "/notes.txt", "allow", nil},
				{"echo m > /proc/1/fd/1", "allow", nil},
				{"echo k >> " + home + "/.ssh/" + kf, "block", keys},
			} {
				action, rules := gap2227Hook(t, api, context.Background(), app, row.command, false)
				if action != row.action || !slices.Equal(rules, row.rules) {
					t.Errorf("laptop %q: %s %v, want %s %v on %s", strings.ReplaceAll(row.command, home, "<home>"), action, rules, row.action, row.rules, runtime.GOOS)
				}
			}
		})
	}
}

// TestGAP2228GuestOwnRootFoldersNeedTheirDirectoryFact: the guest's
// /proc/self/root/tmp is its /tmp, so a strict guest walk needs the same
// directory fact for it as for /tmp, /var/tmp and the home, and an
// eval-built write there fails closed on every gateway OS as the plain
// spelling does (rel-1-0-10:GAP-2228).
func TestGAP2228GuestOwnRootFoldersNeedTheirDirectoryFact(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires an unprivileged POSIX gateway")
	}
	evalKeys := []string{"CMD-EVAL", gap2203KeysRule}
	evalOnly := []string{"CMD-EVAL"}
	rows := []struct {
		command, action string
		rules           []string
	}{
		{"cd /proc/self/root/tmp && eval 'x=f; echo m > $x'", "block", evalKeys},
		{"cd /proc/self/root/var/tmp && eval 'x=f; echo m > $x'", "block", evalKeys},
		{"cd /proc/thread-self/root/home && eval 'x=f; echo m > $x'", "block", evalKeys},
		{"cd /proc/self/root" + sandboxauth.SandboxHome + "/app && eval 'x=notes.txt; echo m >> $x'", "block", evalKeys},
		{"cd /tmp && eval 'x=f; echo m > $x'", "block", evalKeys},
		{"cd /proc/self/root/etc && eval 'x=f; echo m > $x'", "alert", evalOnly},
		{"cd /proc/self/root && eval 'x=f; echo m > $x'", "alert", evalOnly},
		{"cd /proc/self/root/tmp && echo m > notes.txt", "allow", nil},
	}
	for _, pack := range []string{"default", "strict"} {
		t.Run(pack, func(t *testing.T) {
			api, actor, _, _ := gap0545API(t, "claudecode", pack)
			for _, row := range rows {
				action, rules := gap2227Hook(t, api, actor, sandboxauth.SandboxHome+"/app", row.command, true)
				if action != row.action || !slices.Equal(rules, row.rules) {
					t.Errorf("%q: actor %s %v, want %s %v on every gateway OS", row.command, action, rules, row.action, row.rules)
				}
			}
		})
	}
}
