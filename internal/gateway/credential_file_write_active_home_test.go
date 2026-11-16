// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// credentialFileSpellings are the credential files the home-prefixed path
// rules name, with the rule the same name matches outside the active home.
var credentialFileSpellings = []struct {
	rel, rule string
}{
	{".netrc", "PATH-NETRC"},
	{".git-credentials", "PATH-GIT-CREDS"},
	{".aws/credentials", "PATH-AWS-CREDS"},
	{".kube/config", "PATH-KUBE"},
	{".docker/config.json", "PATH-DOCKER"},
	{".npmrc", "PATH-NPMRC"},
	{".pypirc", "PATH-PYPIRC"},
}

// credentialHome is a user home shaped like a login home, /<root>/home/<user>,
// with a project inside it. The user names cover the shapes a directory
// service gives: plain, dotted and hyphenated.
func credentialHome(t *testing.T, user string) (home, project string) {
	t.Helper()
	root := t.TempDir()
	home, project = filepath.Join(root, "home", user), filepath.Join(root, "home", user, "proj")
	if err := os.MkdirAll(project, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("DEFENSECLAW_HOME", t.TempDir())
	t.Chdir(project)
	return home, project
}

var credentialUsers = []string{"alice", "alice.smith", "dc-user"}

// A native patch of a credential file in the active user home gets the
// verdict the same name gets outside it. The read owner of the file must not
// treat a live write as a safe negative and drop the path rule.
func TestPatchOfActiveHomeCredentialFileMatchesTheNameOutsideTheHome(t *testing.T) {
	for _, user := range credentialUsers {
		t.Run(user, func(t *testing.T) { patchOfActiveHomeCredentialFile(t, user) })
	}
}

func patchOfActiveHomeCredentialFile(t *testing.T, user string) {
	home, project := credentialHome(t, user)
	outside := filepath.Join(filepath.Dir(filepath.Dir(home)), "elsewhere", "home", "fixture")
	for _, spelling := range credentialFileSpellings {
		for _, root := range []string{home, outside} {
			file := filepath.Join(root, spelling.rel)
			if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(file, []byte("# base\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, spelling := range credentialFileSpellings {
		for _, tool := range []string{"patch", "apply_patch"} {
			for _, pack := range []string{"", "strict"} {
				patch := func(root string) string {
					return opencodeV2PatchBody(t, project, tool, "*** Begin Patch\n*** Update File: "+
						filepath.Join(root, spelling.rel)+"\n@@\n # base\n+# k\n*** End Patch")
				}
				control := managedOpenCodeHook(t, home, pack, patch(outside))
				got := managedOpenCodeHook(t, home, pack, patch(home))
				if got.action != control.action || !got.rules[spelling.rule] {
					t.Errorf("%s %s pack %q: in-home %s, outside-home %s, want the same verdict by %s",
						tool, spelling.rel, pack, got, control, spelling.rule)
				}
			}
		}
	}
}

// A shell write to a credential file in the active home is judged as the
// name outside it, in every home spelling, and a read or an ordinary file
// next to it keeps the verdict it has.
func TestShellWriteOfActiveHomeCredentialFileMatchesTheNameOutsideTheHome(t *testing.T) {
	for _, user := range credentialUsers {
		t.Run(user, func(t *testing.T) { shellWriteOfActiveHomeCredentialFile(t, user) })
	}
}

func shellWriteOfActiveHomeCredentialFile(t *testing.T, user string) {
	home, project := credentialHome(t, user)
	shell := func(pack, command string) hermesHookOutcome {
		body := string(mustJSON(t, map[string]any{"hook_event_name": "tool.execute.before", "tool_name": "bash",
			"tool_input": map[string]any{"command": command}, "session_id": "session-credfile", "turn_id": "message-1",
			"tool_call_id": "call-1", "agent_name": "build", "cwd": project, "load_heartbeat": true,
			"arguments_authoritative": true, "mcp_identity_status": "not_mcp"}))
		return managedOpenCodeHook(t, home, pack, body)
	}
	for _, spelling := range credentialFileSpellings {
		for _, pack := range []string{"", "strict"} {
			for _, form := range []string{"echo x >> %s", "tee -a %s < /dev/null"} {
				control := shell(pack, fmt.Sprintf(form, "/home/fixture/"+spelling.rel))
				if !control.rules[spelling.rule] {
					t.Fatalf("pack %q %q: the outside-home control does not match %s: %s", pack, form, spelling.rule, control)
				}
				for _, name := range []string{"~/", "$HOME/", "${HOME}/", home + "/"} {
					command := fmt.Sprintf(form, name+spelling.rel)
					if got := shell(pack, command); got.action != control.action || !got.rules[spelling.rule] {
						t.Errorf("pack %q %q: %s, outside the home %s, want the same verdict by %s",
							pack, command, got, control, spelling.rule)
					}
				}
			}
		}
	}
}

// Reading a credential file, or writing a file next to it, keeps its verdict:
// the write lane is not widened to the read lane or to a neighbouring name.
func TestReadAndNeighbourOfActiveHomeCredentialFileKeepTheirVerdict(t *testing.T) {
	home, project := credentialHome(t, "alice")
	shell := func(command string) hermesHookOutcome {
		body := string(mustJSON(t, map[string]any{"hook_event_name": "tool.execute.before", "tool_name": "bash",
			"tool_input": map[string]any{"command": command}, "session_id": "session-credfile", "turn_id": "message-1",
			"tool_call_id": "call-1", "agent_name": "build", "cwd": project, "load_heartbeat": true,
			"arguments_authoritative": true, "mcp_identity_status": "not_mcp"}))
		return managedOpenCodeHook(t, home, "", body)
	}
	// A neighbouring name is allowed; its example file may carry the alert of
	// its name, as it does outside the home.
	if got := shell("echo x >> " + home + "/.netrc.example"); got.action != "allow" {
		t.Errorf("a .netrc.example write: %s, want allow", got)
	}
	for _, command := range []string{
		"echo x >> " + home + "/notes.txt",
		"echo x >> ./netrc",
		"cp " + home + "/.npmrc ./npmrc.copy",
		"git status --short",
	} {
		if got := shell(command); got.action != "allow" || len(got.rules) != 0 {
			t.Errorf("%q: %s, want allow with no rule", command, got)
		}
	}
	for _, name := range []string{".netrc", ".aws/credentials"} {
		got := shell("cat " + home + "/" + name)
		t.Logf("read of %s keeps its verdict: %s", name, got)
	}
}
