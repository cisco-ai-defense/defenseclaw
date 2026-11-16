// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/assetfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enforce"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// shareSkillFixture is a held skill and an ordinary one in a skills root, a
// directory that stands for a network share holding links to both, and two
// directories that stand for shares that never answer. strict selects the
// strict policy tier; held holds the skill.
type shareSkillFixture struct {
	api                 *APIServer
	ctx                 context.Context
	root, live          string
	dead                []string
	connector, projectD string
}

func newShareSkillFixture(t *testing.T, strict, held bool, liveDelay time.Duration) shareSkillFixture {
	t.Helper()
	store, logger := newNativeSkillRuntimeTestStore(t)
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	f := shareSkillFixture{root: filepath.Join(home, ".claude", "skills"), live: filepath.Join(home, "live-share"), connector: "claudecode"}
	f.dead = []string{filepath.Join(home, "dead-share-1"), filepath.Join(home, "dead-share-2")}
	for _, dir := range append([]string{f.live, filepath.Join(home, "proj")}, f.dead...) {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"held", "ordinary"} {
		if err := os.MkdirAll(filepath.Join(f.root, name), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(f.root, name, "SKILL.md"), []byte("---\nname: "+name+"\n---\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(f.root, name), filepath.Join(f.live, "lnk-"+name)); err != nil {
			t.Skipf("cannot create a link here: %v", err)
		}
	}
	if err := os.Symlink(filepath.Join("..", ".claude", "skills", "held"), filepath.Join(f.live, "lnk-relative")); err != nil {
		t.Skipf("cannot create a link here: %v", err)
	}
	if held {
		if err := enforce.NewPolicyEngine(store).Disable("skill", "held", "quarantine failed"); err != nil {
			t.Fatal(err)
		}
	}
	cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	if strict {
		cfg.Guardrail.Mode = "action"
		cfg.Guardrail.Connector = f.connector
		cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), "strict")
	}
	f.api = &APIServer{store: store, logger: logger, scannerCfg: cfg}
	f.ctx = withManagedHookPeer(context.Background(), managedHookPeer{UID: 1001, Name: "fixture", Home: home})
	f.projectD = filepath.Join(home, "proj")
	release := make(chan struct{})
	restore := hookpaths.OverrideNetworkSharesForTest(func(path string) string {
		for _, root := range append([]string{f.live}, f.dead...) {
			if path == root || strings.HasPrefix(path, root+string(filepath.Separator)) {
				return root
			}
		}
		return ""
	}, func(root string) {
		if strings.TrimRight(root, string(filepath.Separator)) == f.live {
			time.Sleep(liveDelay)
			return
		}
		<-release
	})
	t.Cleanup(func() {
		close(release)
		restore()
	})
	return f
}

// spend asks the shares that never answer first, as a hook call that named
// them did, so the call has no wait left for the next share.
func (f shareSkillFixture) spend(t *testing.T) {
	t.Helper()
	for _, dir := range f.dead {
		if _, err := hookpaths.Lstat(filepath.Join(dir, "notes.txt")); err == nil {
			t.Fatal("the share that does not answer answered")
		}
	}
}

func (f shareSkillFixture) decide(tool, key, value string, claims assetfacts.Facts) (config.AssetPolicyDecision, bool) {
	ctx := context.WithValue(f.ctx, claimedAssetFactsContextKey{}, claims)
	return f.api.claudeCodeSkillAssetDecision(ctx, claudeCodeHookRequest{
		HookEventName: "PreToolUse", ToolName: tool, CWD: f.projectD,
		ToolInput: map[string]interface{}{key: value},
	})
}

// A link on a network share that answers leads to the held skill folder as a
// link on a local disk does: the call is refused in every tier, for a read, a
// shell reader and a link written relative to the share, and a link on the
// same share to an ordinary skill stays allowed.
func TestLinkOnAnAnsweringShareToAHeldSkillFolderIsRefused(t *testing.T) {
	for _, strict := range []bool{false, true} {
		f := newShareSkillFixture(t, strict, true, 50*time.Millisecond)
		defer hookpaths.HookCall()()
		for name, tc := range map[string]struct{ tool, key, value string }{
			"link read":     {"Read", "file_path", filepath.Join(f.live, "lnk-held", "SKILL.md")},
			"relative link": {"Read", "file_path", filepath.Join(f.live, "lnk-relative", "SKILL.md")},
			"shell reader":  {"Bash", "command", "cat " + filepath.Join(f.live, "lnk-held", "SKILL.md")},
			"folder glob":   {"Glob", "path", filepath.Join(f.live, "lnk-held")},
		} {
			if decision, matched := f.decide(tc.tool, tc.key, tc.value, assetfacts.Facts{}); !matched || decision.Action != "block" {
				t.Errorf("strict=%t %s: %s %q was allowed, want the held skill refused", strict, name, tc.tool, tc.value)
			}
		}
		for name, tc := range map[string]struct{ tool, key, value string }{
			"link to an ordinary skill": {"Read", "file_path", filepath.Join(f.live, "lnk-ordinary", "SKILL.md")},
			"file on the share":         {"Read", "file_path", filepath.Join(f.live, "notes.txt")},
		} {
			if decision, matched := f.decide(tc.tool, tc.key, tc.value, assetfacts.Facts{}); matched && decision.Action == "block" {
				t.Errorf("strict=%t %s: %s %q was refused: %s", strict, name, tc.tool, tc.value, decision.Reason)
			}
		}
	}
}

// A share that the hook call's wait was spent before it could answer leaves
// the link on it unproven. With a skill held, the strict tier refuses the call
// as unproven and the default tier allows it with an alert (the audit row);
// the held folder named directly is refused in both, and with no skill held
// or denied the ordinary call runs in both.
func TestLinkOnAShareTheCallWaitCutShortIsJudgedByTheTier(t *testing.T) {
	read := func(f shareSkillFixture, claims assetfacts.Facts) (config.AssetPolicyDecision, bool) {
		return f.decide("Read", "file_path", filepath.Join(f.live, "lnk-ordinary", "SKILL.md"), claims)
	}
	for _, row := range []struct {
		name         string
		strict, held bool
		wantBlock    bool
	}{
		{"strict-held", true, true, true},
		{"default-held", false, true, false},
		{"strict-nothing-held", true, false, false},
		{"default-nothing-held", false, false, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			f := newShareSkillFixture(t, row.strict, row.held, 600*time.Millisecond)
			defer hookpaths.HookCall()()
			f.spend(t)
			decision, matched := read(f, assetfacts.Facts{})
			if blocked := matched && decision.Action == "block"; blocked != row.wantBlock {
				t.Fatalf("a link on a share the wait was cut short: blocked=%t, want %t (%+v)", blocked, row.wantBlock, decision)
			}
			if row.wantBlock && decision.Source != "skill-links-unproven" {
				t.Errorf("source = %q, want skill-links-unproven", decision.Source)
			}
			// A held folder the call names itself is refused in every tier.
			if direct, matched := f.decide("Read", "file_path", filepath.Join(f.root, "held", "SKILL.md"), assetfacts.Facts{}); row.held && (!matched || direct.Action != "block") {
				t.Errorf("the held folder named directly was allowed")
			}
		})
	}
	// With the call's wait whole the same share answers and the ordinary link
	// is allowed in the strict tier too.
	f := newShareSkillFixture(t, true, true, 50*time.Millisecond)
	defer hookpaths.HookCall()()
	if decision, matched := read(f, assetfacts.Facts{}); matched && decision.Action == "block" {
		t.Errorf("a link to an ordinary skill on a share that answered was refused: %s", decision.Reason)
	}
}

// The standalone hook's claim that a share did not answer in its wait is
// judged the same way, for a gateway that does not ask the share itself.
func TestClaimedUnprovenSkillLinksAreJudgedByTheTier(t *testing.T) {
	for _, row := range []struct {
		name         string
		strict, held bool
		wantBlock    bool
	}{
		{"strict-held", true, true, true},
		{"default-held", false, true, false},
		{"strict-nothing-held", true, false, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			f := newShareSkillFixture(t, row.strict, row.held, 50*time.Millisecond)
			defer hookpaths.HookCall()()
			decision, matched := f.decide("Read", "file_path", filepath.Join(f.projectD, "notes.txt"), assetfacts.Facts{SkillLinksUnproven: true})
			if blocked := matched && decision.Action == "block"; blocked != row.wantBlock {
				t.Fatalf("an unproven claim: blocked=%t, want %t (%+v)", blocked, row.wantBlock, decision)
			}
		})
	}
}
