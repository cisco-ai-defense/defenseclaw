// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

func TestGAP0483PlainTouchMissingLeavesSkipPathWalk(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	key := filepath.Join(home, ".ssh", "authorized_keys")
	if err := os.MkdirAll(cwd, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(key), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	names := make([]string, 2000)
	for i := range names {
		names[i] = fmt.Sprintf("lo%d.txt", i)
	}
	command := "touch " + strings.Join(names, " ")
	memo := NewTargetMemo()
	if got := memo.ActionCommandDecisionWithDialectAndGlobFacts(command, cwd, home, actionfacts.DialectPOSIX, nil); got != "" {
		t.Fatalf("ordinary leaves = %q, want allow", got)
	}
	if walked, _ := memo.WorkParts(); walked > 64 {
		t.Fatalf("ordinary leaves walked %d path parts, want at most 64", walked)
	}
	for _, index := range []int{0, len(names) / 2, len(names) - 1} {
		withKey := append([]string(nil), names...)
		withKey[index] = "../.ssh/authorized_keys"
		if got := ActionCommandDecision("touch "+strings.Join(withKey, " "), cwd, home); got != "protected-target" {
			t.Fatalf("key path at %d = %q, want protected-target", index, got)
		}
	}
	link := filepath.Join(cwd, names[len(names)/2])
	if err := os.Symlink(key, link); err != nil {
		t.Fatal(err)
	}
	if got := ActionCommandDecision(command, cwd, home); got != "protected-target" {
		t.Fatalf("existing link = %q, want protected-target", got)
	}
}
