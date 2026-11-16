// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"runtime"
	"testing"
	"time"
)

// TestCredentialFileCopyIsJudgedLikeItsReadFiveTiers: a copy reads its source
// as a cat does, so the credential file that cp, rsync or install moves to a
// staging folder gets the verdict of cat on the same file in every tier
// (Phase-1 tune side class "credential-file read": PATH-SSH-KEY alone counted
// the copy, the rules of the AWS, kube, docker, git, netrc, npm, pypi,
// /proc/self/environ and cloud-token files read cat-like reads only). A
// template, a project copy and a neighbouring name stay allowed. The read is
// the oracle, never a hard-coded letter, so a later change of a rule's
// severity moves both together. A copy of the account's own .git-credentials
// or .netrc keeps the stronger verdict rel gives it (the lead ruling of
// 2026-11-16, TestOwnDeveloperTokenCopyKeepsTheRelTierFiveTiers), while their
// read keeps the alert of GAP-0888: for those two the copy is never weaker
// than the read.
func TestCredentialFileCopyIsJudgedLikeItsReadFiveTiers(t *testing.T) {
	files := []string{
		"~/.aws/credentials", "~/.kube/config", "~/.docker/config.json", "~/.git-credentials",
		"~/.netrc", "~/.npmrc", "~/.pypirc", "/proc/self/environ",
		"~/.config/gcloud/application_default_credentials.json",
	}
	for _, p := range gap0437Packs {
		a := gap0437Server(t, p, "openclaw", "action")
		// Policy semantics, not latency: a slow host (the Windows runner)
		// must not turn a verdict into a 504 scan timeout.
		a.inspectToolScanTimeout = 30 * time.Second
		warmDefenseClawControl(t, a.handleInspectTool, "/api/v1/inspect/tool", map[string]any{
			"tool": "exec", "connector": "openclaw", "args": map[string]any{"command": "ls", "workdir": t.TempDir()},
		})
		for _, file := range files {
			if runtime.GOOS == "windows" && file == "/proc/self/environ" {
				continue // no /proc on a Windows host
			}
			read, _ := tdetectVerdict(t, a, "cat "+file)
			if read == "allow" && p.pack != "permissive" {
				t.Errorf("%s: cat %s is allowed, the oracle needs a verdict", p.name, file)
			}
			atLeast := file == "~/.git-credentials" || file == "~/.netrc"
			rank := map[string]int{"allow": 0, "alert": 1, "block": 2}
			for _, form := range []string{"cp %s /tmp/staged", "rsync -a %s /tmp/staged", "install %s /tmp/staged"} {
				command := fmt.Sprintf(form, file)
				got, out := tdetectVerdict(t, a, command)
				if atLeast && rank[got] < rank[read] || !atLeast && got != read {
					t.Errorf("%s: %q is %s, its read is %s: %v", p.name, command, got, read, out)
				}
			}
		}
		for _, command := range []string{
			"cp ~/.aws/credentials.example /tmp/staged",
			"cp ~/.aws/config /tmp/staged",
			"cp ./proj/.aws/credentials /tmp/staged",
			"cp ~/.bashrc /tmp/staged",
			"cp ~/proj/README.md /tmp/staged",
		} {
			if got, out := tdetectVerdict(t, a, command); got != "allow" {
				t.Errorf("%s: %q is %s, want allow: %v", p.name, command, got, out)
			}
		}
	}
}
