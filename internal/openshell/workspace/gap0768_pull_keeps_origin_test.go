//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package workspace

import (
	"strings"
	"testing"
)

// RV-T6A (GAP-0768): the origin this computer recorded at upload is what
// pull --push-branch pushes to. A pull of a copy whose agent pointed origin
// elsewhere blocks on it and never writes the agent's address into the
// record.
func TestGAP0768PullNeverRewritesTheRecordedOrigin(t *testing.T) {
	const origin, fork = "https://git.example.test/team/app.git", "https://git.example.test/team/fork.git"
	e := newEnv(t)
	e.initRepo()
	e.git(e.project, "remote", "add", "origin", origin)
	_, fs := launchCopy(t, e, "c1", nil)
	fs.agent(remoteRepo, "remote", "set-url", "origin", fork)
	fs.agent(remoteRepo, "remote", "add", "extra", fork)
	fs.write(remoteRepo+"/README.md", "agent version\n")
	pr := pull(t, e, fs, "c1")
	if b := strings.Join(pr.Blocking, "; "); !strings.Contains(b, `remote "origin" now points to `+fork) || !strings.Contains(b, `new remote "extra"`) {
		t.Fatalf("blocking = %q", b)
	}
	rec, err := LoadCopy(e.data, "c1")
	if err != nil {
		t.Fatal(err)
	}
	if rec.Remotes["origin"] != origin || rec.Remotes["extra"] != "" {
		t.Fatalf("the record's remotes after the pull: %v", rec.Remotes)
	}
}
