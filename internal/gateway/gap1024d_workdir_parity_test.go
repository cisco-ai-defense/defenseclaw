// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
)

// TestGAP1024dAbsoluteSessionWorkdirMatchesLaptop pins the copy-mode actor
// against the laptop when an absolute session folder and a shell tool's own
// workdir are both present. The local and guest homes have the same layout.
func TestGAP1024dAbsoluteSessionWorkdirMatchesLaptop(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires an unprivileged POSIX gateway")
	}
	sshFolder := "~/" + ".ssh"
	cases := []struct {
		workdir, command string
	}{
		{"~", strings.Join([]string{"tar", "cz", sshFolder}, " ")},
		{"~/src", strings.Join([]string{"cp", "-r", sshFolder, "/tmp/x"}, " ")},
		{"~/src", strings.Join([]string{"tar", "cz", ".ssh"}, " ")},
		{"src", strings.Join([]string{"tar", "cz", ".ssh"}, " ")},
		{"-", strings.Join([]string{"tar", "cz", sshFolder}, " ")},
	}
	for _, pack := range []string{"default", "strict"} {
		for _, shape := range gap0545Shapes() {
			if shape.connector != "codex" || shape.name != "codex exec_command cmd" {
				if shape.connector != "amp" {
					continue
				}
			}
			t.Run(pack+"/"+shape.name, func(t *testing.T) {
				api, actor, home, _ := gap0545API(t, shape.connector, pack)
				for _, dir := range []string{".ssh", "src"} {
					if err := os.MkdirAll(filepath.Join(home, dir), 0o700); err != nil {
						t.Fatal(err)
					}
				}
				if err := os.WriteFile(filepath.Join(home, ".ssh", "authorized_keys"), []byte("x\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				for _, tc := range cases {
					mk := func(cwd string) []byte {
						body := shape.body(tc.command, cwd)
						if tool, ok := body["tool_input"].(map[string]any); ok && tc.workdir != "-" {
							for _, key := range []string{"workdir", "cwd"} {
								if _, has := tool[key]; has {
									tool[key] = tc.workdir
								}
							}
						} else if ok {
							delete(tool, "workdir")
							delete(tool, "cwd")
						}
						raw, err := json.Marshal(body)
						if err != nil {
							t.Fatal(err)
						}
						return raw
					}
					localAction, localRules := gap0545Verdict(t, api, context.Background(), shape, mk(home))
					actorAction, actorRules := gap0545Verdict(t, api, actor, shape, mk(sandboxauth.SandboxHome))
					kitAction, kitRules := gap0545Verdict(t, api,
						gap0545Actor(actor, shape.connector, shape.event, mk(sandboxauth.SandboxHome),
							gap0545KitFacts(t, shape.connector, shape.event, mk(home), home)),
						shape, mk(sandboxauth.SandboxHome))
					if kitAction != localAction || !slices.Equal(kitRules, localRules) {
						t.Errorf("kit workdir=%q command=%q: laptop %s %v, kit %s %v",
							tc.workdir, tc.command, localAction, localRules, kitAction, kitRules)
					}
					if localAction != actorAction || !slices.Equal(localRules, actorRules) {
						t.Errorf("workdir=%q command=%q: laptop %s %v, actor %s %v",
							tc.workdir, tc.command, localAction, localRules, actorAction, actorRules)
					}
				}
			})
		}
	}
}
