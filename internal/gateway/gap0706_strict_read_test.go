// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// TestGAP0706StrictCredentialContentReadBlocks is substrate-1:GAP-0706 part
// 2 (owner ruling 2026-11-19, hardening 1.0.11): the strict pack blocks a
// proven content read of a credential file (cat, head, base64 of the file
// itself), from the home or spelled relative to it. The default pack keeps
// the alert and the permissive pack its allow. A read of no content (head
// -c 0, wc, ls), a project .env, shell history, the SSH
// folder's other files and a project file named like a credential file keep
// their verdicts.
func TestGAP0706StrictCredentialContentReadBlocks(t *testing.T) {
	installCorrelationHMACForTest(t)
	home := filepath.Join(t.TempDir(), "home", "alice")
	for _, d := range []string{".aws", ".kube", ".docker", ".ssh", "proj"} {
		if err := os.MkdirAll(filepath.Join(home, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	reads := []string{
		"cat ~/.aws/credentials", "cat .aws/credentials", "head -5 ~/.aws/credentials",
		"base64 ~/.aws/credentials", "cat ~/.kube/config", "cat ~/.git-credentials",
		"cat ~/.netrc", "cat ~/.docker/config.json",
	}
	notBlocked := []string{
		"head -c 0 ~/.aws/credentials", "wc -l ~/.aws/credentials", "ls -la ~/.aws",
		"cat proj/.env",
		"cat ~/.bash_history", "cat ~/.ssh/known_hosts",
	}
	allowed := []string{"cat proj/credentials.py", "cat proj/config", "cat proj/README.md"}
	for _, pack := range []string{"default", "permissive", "strict"} {
		handler := hostClaudeHookHandlerForTest(t, pack)
		n := 0
		verdict := func(cmd string) string {
			n++
			ev := claudeToolEvent("PreToolUse", "g0706r-"+pack+strconv.Itoa(n), "c"+strconv.Itoa(n), cmd)
			ev["cwd"] = home
			return callAgentHookForTest(t, handler, ev).Action
		}
		want := map[string]string{"default": "alert", "permissive": "allow", "strict": "block"}[pack]
		for _, cmd := range reads {
			if got := verdict(cmd); got != want {
				t.Errorf("%s: credential read %q = %s, want %s", pack, cmd, got, want)
			}
		}
		for _, cmd := range notBlocked {
			if got := verdict(cmd); got == "block" {
				t.Errorf("%s: control %q = block, want its non-block verdict", pack, cmd)
			}
		}
		for _, cmd := range allowed {
			if got := verdict(cmd); got != "allow" {
				t.Errorf("%s: control %q = %s, want allow", pack, cmd, got)
			}
		}
	}
}
