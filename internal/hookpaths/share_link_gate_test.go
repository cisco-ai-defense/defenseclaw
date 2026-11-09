// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/assetfacts"
)

// shareLinkFixture is a skills root with a held folder, and three directories
// that stand for network shares: one holds links to the held folder and to an
// ordinary one, the others hold nothing.
func shareLinkFixture(t *testing.T) (held, ordinary, live string, dead []string) {
	t.Helper()
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	held = filepath.Join(home, ".claude", "skills", "held")
	ordinary = filepath.Join(home, ".claude", "skills", "ordinary")
	live = filepath.Join(home, "live-share")
	dead = []string{filepath.Join(home, "dead-share-1"), filepath.Join(home, "dead-share-2")}
	for _, dir := range append([]string{held, ordinary, live}, dead...) {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for name, target := range map[string]string{"lnk-held": held, "lnk-ordinary": ordinary, "lnk-rel": filepath.Join("..", ".claude", "skills", "held")} {
		if err := os.Symlink(target, filepath.Join(live, name)); err != nil {
			t.Skipf("cannot create a link here: %v", err)
		}
	}
	return held, ordinary, live, dead
}

// A link on a share that answers leads where it leads: the walk shows the
// held skill folder as it shows one reached through a link on a local disk,
// and an ordinary folder stays ordinary. The call records nothing unproven.
func TestLinkWalkFollowsLinksOnAShareThatAnswers(t *testing.T) {
	held, ordinary, live, _ := shareLinkFixture(t)
	fakeNetworkShares(t, []string{live}, 750*time.Millisecond, func(string) {})
	defer HookCall()()
	for _, row := range []struct{ path, want string }{
		{filepath.Join(live, "lnk-held", "SKILL.md"), filepath.Join(held, "SKILL.md")},
		{filepath.Join(live, "lnk-rel", "SKILL.md"), filepath.Join(held, "SKILL.md")},
		{filepath.Join(live, "lnk-held", "sub", "..", "SKILL.md"), filepath.Join(held, "SKILL.md")},
		{filepath.Join(live, "lnk-ordinary", "SKILL.md"), filepath.Join(ordinary, "SKILL.md")},
	} {
		if got := assetfacts.ResolveLinks(row.path); got != row.want {
			t.Errorf("ResolveLinks(%q) = %q, want %q", row.path, got, row.want)
		}
	}
	if SkillLinksUnproven() {
		t.Error("the links of a share that answered were recorded as unproven")
	}
}

// A share that does not answer within its own wait (the owner-accepted bound)
// is not read: the path stays as spelled, at once, and nothing is recorded.
func TestLinkWalkDoesNotReadAShareThatDoesNotAnswer(t *testing.T) {
	_, _, live, _ := shareLinkFixture(t)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	fakeNetworkShares(t, []string{live}, 100*time.Millisecond, func(string) { <-release })
	defer HookCall()()
	path := filepath.Join(live, "lnk-held", "SKILL.md")
	start := time.Now()
	if got := assetfacts.ResolveLinks(path); got != path {
		t.Errorf("ResolveLinks(%q) = %q, want it as spelled", path, got)
	}
	if took := time.Since(start); took > time.Second {
		t.Errorf("ResolveLinks took %v, want the wait of the share and no more", took)
	}
	if SkillLinksUnproven() {
		t.Error("a share that did not answer within its own wait was recorded as unproven")
	}
}

// A share that might have answered had the call had budget left is recorded:
// after shares that do not answer have spent the wait of the call, a share
// that answers in time for its own wait is cut short, and the link on it is
// unproven. With the budget to spare the same share is followed.
func TestLinkWalkRecordsAShareTheCallBudgetCutShort(t *testing.T) {
	held, _, live, dead := shareLinkFixture(t)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	fakeNetworkShares(t, append([]string{live}, dead...), 100*time.Millisecond, func(root string) {
		if root == live {
			time.Sleep(90 * time.Millisecond)
			return
		}
		<-release
	})
	path := filepath.Join(live, "lnk-held", "SKILL.md")
	func() {
		defer HookCall()()
		for _, dir := range dead {
			if got := assetfacts.ResolveLinks(filepath.Join(dir, "x")); got != filepath.Join(dir, "x") {
				t.Fatalf("ResolveLinks(%q) = %q", dir, got)
			}
		}
		if got := assetfacts.ResolveLinks(path); got != path {
			t.Errorf("after the budget was spent, ResolveLinks(%q) = %q, want it as spelled", path, got)
		}
		if !SkillLinksUnproven() {
			t.Error("a share the call budget cut short was not recorded as unproven")
		}
	}()
	// The same share, asked by a call with its budget whole, answers.
	fakeNetworkShares(t, []string{live}, 100*time.Millisecond, func(string) { time.Sleep(60 * time.Millisecond) })
	defer HookCall()()
	if got, want := assetfacts.ResolveLinks(path), filepath.Join(held, "SKILL.md"); got != want {
		t.Errorf("with the budget to spare, ResolveLinks(%q) = %q, want %q", path, got, want)
	}
	if SkillLinksUnproven() {
		t.Error("a share that answered was recorded as unproven")
	}
}
