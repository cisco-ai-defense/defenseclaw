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

// gap2203KeysRule is the rule a gateway host's own folder links add to the
// laptop's answer on macOS (gap2203HostLinksSystemFolders).
const gap2203KeysRule = "persistence.ssh_authorized_keys_command"

// gap2203HostLinksSystemFolders reports a gateway host whose own /tmp or
// /etc is a link (macOS: into /private). The laptop is that host, so its
// reading of a cd through those folders may fail closed where a Linux
// laptop's does not; a sandbox guest shares none of the host's links.
func gap2203HostLinksSystemFolders() bool {
	for _, folder := range []string{"/tmp", "/etc"} {
		if info, err := os.Lstat(folder); err == nil && info.Mode()&os.ModeSymlink != 0 {
			return true
		}
	}
	return false
}

// gap2203LinuxAnswers are the copy-mode actor's answers, in every pack, to
// the rows of gap0377Check where a macOS laptop adds the keys rule through
// the host's /etc or /tmp link: the answers a Linux gateway gives the actor
// and the laptop, pinned so that every gateway OS must give the actor the
// same (rel-1-0-10:GAP-2203).
var gap2203LinuxAnswers = map[string]struct {
	action string
	rules  []string
}{
	"cdpath-inline b-write":  {"allow", nil},
	"cdpath-inline bashrc":   {"alert", []string{"ACTION-COMPOUND-LIMIT", "persistence.shell_profile_write"}},
	"cdpath-inline settings": {"alert", []string{"tamper.agent_hook_config_write"}},
	"win-hs-63 settings":     {"alert", []string{"tamper.agent_hook_config_write"}},
}

// gap2203PinnedActorAnswer checks a gap0377Check row pinned in
// gap2203LinuxAnswers: the actor must give the Linux answer on every
// gateway OS. It reports true when the laptop's answer is that answer plus
// only the keys rule on a host that links its system folders, the host's
// own fail-closed reading that the actor does not share, so the caller
// skips the actor-versus-laptop checks for the row.
func gap2203PinnedActorAnswer(t *testing.T, name, laptop string, laptopRules []string, actor string, actorRules []string) bool {
	t.Helper()
	want, pinned := gap2203LinuxAnswers[name]
	if !pinned {
		return false
	}
	if actor != want.action || !slices.Equal(actorRules, want.rules) {
		t.Errorf("%s: copy-mode actor %s %v, want the Linux answer %s %v on every gateway OS", name, actor, actorRules, want.action, want.rules)
	}
	hostOnly := slices.DeleteFunc(slices.Clone(laptopRules), func(rule string) bool { return rule == gap2203KeysRule })
	return gap2203HostLinksSystemFolders() && laptop != "allow" && len(hostOnly) == len(laptopRules)-1 &&
		slices.Equal(hostOnly, want.rules)
}

// TestGAP2203SandboxGuestFoldersFollowTheLinuxLayout: a copy-mode actor runs
// in a Linux guest whose files the gateway cannot open, so a cd into the
// guest's home, /home, /tmp or /var/tmp before a write whose target the
// call builds at run time fails closed, and no folder the guest names is
// placed through the gateway host's own folder links. A macOS gateway
// resolved the guest's /tmp, /var/tmp and /sandbox on the host and allowed
// with an alert what a Linux gateway blocks (rel-1-0-10:GAP-2203). The actor
// gets the Linux gateway's answer on every gateway OS; the laptop keeps its
// own host's answer (CMD-EVAL alert for the eval rows).
func TestGAP2203SandboxGuestFoldersFollowTheLinuxLayout(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires an unprivileged POSIX gateway")
	}
	kf := "authorized_" + "keys"
	keys := []string{gap2203KeysRule}
	evalKeys := []string{"CMD-EVAL", gap2203KeysRule}
	evalOnly := []string{"CMD-EVAL"}
	rows := []struct {
		command, action string
		rules           []string
	}{
		{"cd /tmp && eval 'x=f; echo m > $x'", "block", evalKeys},
		{"cd /var/tmp && eval 'x=f; echo m > $x'", "block", evalKeys},
		{"cd /home && eval 'x=f; echo m > $x'", "block", evalKeys},
		{"cd " + sandboxauth.SandboxHome + "/app && eval 'x=notes.txt; echo m >> $x'", "block", evalKeys},
		{"cd /etc && eval 'x=f; echo m > $x'", "alert", evalOnly},
		{"cd /var && eval 'x=f; echo m > $x'", "alert", evalOnly},
		{"cd /opt && eval 'x=f; echo m > $x'", "alert", evalOnly},
		{"cd /private/tmp && eval 'x=f; echo m > $x'", "alert", evalOnly},
		{`cd /tmp && eval "echo m > $F"`, "alert", evalOnly},
		{"cd /etc && echo k >> ../sandbox/.ssh/" + kf, "block", keys},
		{"cd /tmp && echo k >> ../sandbox/.ssh/" + kf, "block", keys},
		{"cd /var/tmp && echo k >> ../../sandbox/.ssh/" + kf, "block", keys},
		{"cd -P /tmp && echo k >> ../sandbox/.ssh/" + kf, "block", keys},
		{"cd -P /etc && echo k >> ../sandbox/.ssh/" + kf, "block", keys},
		{"cd /etc/../sandbox/.ssh && echo k >> " + kf, "block", keys},
		{"cd /tmp && echo m > notes.txt", "allow", nil},
		{"cd /etc && cat hosts > " + sandboxauth.SandboxHome + "/app/h.txt", "allow", nil},
		{"cd " + sandboxauth.SandboxHome + " && echo m > app/notes.txt", "allow", nil},
	}
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
				body, _ := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "session_id": "gap2203",
					"cwd": sandboxauth.SandboxHome + "/app", "tool_name": "Bash", "tool_input": map[string]any{"command": row.command},
					"tool_use_id": "gap2203"})
				action, rules := hook(gap0545Actor(actor, "claudecode", "PreToolUse", body, nil), body)
				if action != row.action || !slices.Equal(rules, row.rules) {
					t.Errorf("%q: actor %s %v, want the Linux gateway's %s %v on every gateway OS", row.command, action, rules, row.action, row.rules)
				}
			}
		})
	}
}
