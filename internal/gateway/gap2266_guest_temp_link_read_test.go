// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
)

// gap2266Hook sends one claudecode PreToolUse Bash call as the sandbox actor
// and returns the action the gateway answers.
func gap2266Hook(t *testing.T, api *APIServer, actor context.Context, cwd, command string) string {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "session_id": "gap2266",
		"cwd": cwd, "tool_name": "Bash", "tool_input": map[string]any{"command": command}, "tool_use_id": "gap2266"})
	ctx := gap0545Actor(actor, "claudecode", "PreToolUse", body, nil)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/claudecode/hook", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	api.handleAgentHook("claudecode").ServeHTTP(rec, req.WithContext(ctx))
	var out struct {
		Action string `json:"action"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return out.Action
}

// A sandbox guest that makes a relative link in its temp folder toward a
// folder of its home, and then reads through it, reads the file its plain
// spelling names, never less than its plain read. The guest is Linux
// whatever OS the gateway runs on: the gateway host's own spelling of that
// temp folder (a link to a private folder on macOS) does not move the
// guest's link target, so every gateway OS gives the answer the Linux
// gateway gives (rel-1-0-10:GAP-2266). Rows are
// reported by id, never by command text; the words are joined at run time.
func TestGAP2266GuestTempLinkReadMatchesPlainRead(t *testing.T) {
	home := sandboxauth.SandboxHome
	tmp := "/" + "tmp"
	keyDir := "." + "ssh"
	keyFile := strings.Join([]string{"authorized", "keys"}, "_")
	notes := "notes"
	up := func(dir string) string {
		return strings.Join([]string{"..", strings.TrimPrefix(home, "/"), dir}, "/")
	}
	and := " && "
	// want is the answer of the Linux gateway, the one every gateway OS
	// gives (GAP-2223 contract); "" means the answer of the plain read.
	type row struct {
		id, command, plain, want string
		exact                    bool
	}
	rows := []row{
		{"r0-cd-relative-name", "cd " + tmp + and + "ln -s " + up(keyDir) + " d" + and + "cat d/" + keyFile,
			"cat " + home + "/" + keyDir + "/" + keyFile, "block", false},
		{"r1-absolute-name", "ln -s " + up(keyDir) + " " + tmp + "/d" + and + "cat " + tmp + "/d/" + keyFile,
			"cat " + home + "/" + keyDir + "/" + keyFile, "", false},
		{"r2-cd-head", "cd " + tmp + and + "ln -s " + up(keyDir) + " d" + and + "head -1 d/" + keyFile,
			"head -1 " + home + "/" + keyDir + "/" + keyFile, "block", false},
		// An ordinary folder read through the same kind of link keeps the
		// answer of its plain read: the link adds nothing.
		{"s0-cd-ordinary", "cd " + tmp + and + "ln -s " + up(notes) + " d" + and + "cat d/a.txt",
			"cat " + home + "/" + notes + "/a.txt", "", true},
	}
	rank := map[string]int{"allow": 0, "alert": 1, "block": 2}
	for _, pack := range []string{"default", "strict"} {
		t.Run(pack, func(t *testing.T) {
			api, actor, _, _ := gap0545API(t, "claudecode", pack)
			cwd := home + "/app"
			for _, r := range rows {
				plain := gap2266Hook(t, api, actor, cwd, r.plain)
				got := gap2266Hook(t, api, actor, cwd, r.command)
				if rank[got] < rank[plain] || r.exact && got != plain {
					t.Errorf("%s: %s, plain read %s", r.id, got, plain)
				}
				if r.want != "" && got != r.want {
					t.Errorf("%s: %s, the Linux gateway answers %s", r.id, got, r.want)
				}
			}
		})
	}
}
