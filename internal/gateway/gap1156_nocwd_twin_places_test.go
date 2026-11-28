// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
)

// gap1156NoCwdCommand writes through alias in the start folder and then
// reads the same spelling in docs, where it is a benign link. pad statements
// in between put the call past the statement budget and the read past the
// first 32 path facts the kit sends.
func gap1156NoCwdCommand(alias string, pad int) string {
	var out strings.Builder
	out.WriteString(strings.Join([]string{"echo", "k", ">>", alias}, " "))
	out.WriteString("; ")
	for i := range pad {
		fmt.Fprintf(&out, "test -e f%d && :;", i)
	}
	out.WriteString(strings.Join([]string{"cd", "docs", "&&", "cat", alias}, " "))
	out.WriteString("; :")
	return out.String()
}

// TestGAP1156NoCwdDuplicateWordKeepsEveryPlace: a Claude Code actor call
// with no top-level cwd (the kit reads its words in its own folder) that
// writes through a protected link and then reads the same spelling in a
// folder where it is a benign link gets the answer the same call with the
// cwd gets: the gateway reads the spelling once per place instead of
// dropping its claim. Over the statement budget the second place is a late
// link fact; under it both places are in the first 32 (substrate-1
// GAP-1156, CHK-T6-1156 hold 1).
func TestGAP1156NoCwdDuplicateWordKeepsEveryPlace(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires an unprivileged POSIX gateway")
	}
	claude := gap0545Shapes()[0]
	for _, alias := range []string{"ak" + "-link", "dc" + "-link"} {
		for _, pad := range []int{0, 88} {
			for _, c := range []struct{ pack, mode string }{
				{"default", "action"}, {"strict", "action"}, {"permissive", "action"}, {"default", "observe"},
			} {
				t.Run(fmt.Sprintf("%s/pad%d/%s/%s", alias, pad, c.pack, c.mode), func(t *testing.T) {
					api, actor, home, app := gap0545API(t, "claudecode", c.pack)
					api.scannerCfg.Guardrail.Mode = c.mode
					if err := os.Symlink("README.md", filepath.Join(app, "docs", alias)); err != nil {
						t.Fatal(err)
					}
					t.Chdir(app)
					command := gap1156NoCwdCommand(alias, pad)
					body := func(cwd string) []byte {
						m := map[string]any{"hook_event_name": "PreToolUse", "session_id": "s", "tool_name": "Bash",
							"tool_input": map[string]any{"command": command}}
						if cwd != "" {
							m["cwd"] = cwd
						}
						raw, _ := json.Marshal(m)
						return raw
					}
					verdict := func(hostCwd, guestCwd string) (string, []string) {
						facts := gap0545KitFacts(t, "claudecode", "PreToolUse", body(hostCwd), home)
						guest := body(guestCwd)
						return gap0545Verdict(t, api, gap0545Actor(actor, "claudecode", "PreToolUse", guest, facts), claude, guest)
					}
					wa, wr := verdict(app, sandboxauth.SandboxHome+"/app")
					na, nr := verdict("", "")
					t.Logf("with cwd %s %v, no cwd %s %v", wa, wr, na, nr)
					if gap0545Rank(wa, wr) < 2 {
						t.Fatalf("with cwd %s %v, want an alert or a block (the test layout is wrong)", wa, wr)
					}
					if gap0545Rank(na, nr) < gap0545Rank(wa, wr) {
						t.Errorf("no cwd %s %v is weaker than with cwd %s %v", na, nr, wa, wr)
					}
					for _, rule := range wr {
						if !slices.Contains(nr, rule) {
							t.Errorf("no cwd %s %v does not name %s (with cwd %s %v)", na, nr, rule, wa, wr)
						}
					}
				})
			}
		}
	}
}
