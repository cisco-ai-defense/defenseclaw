// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enforce"
)

func policyHoldEntryFor(copies ...string) *audit.ActionEntry {
	keys := make([]string, 0, len(copies))
	for _, copy := range copies {
		keys = append(keys, policyCopyKey(copy))
	}
	return &audit.ActionEntry{
		Actions: audit.ActionState{Runtime: "disable"},
		Reason:  quarantineFailedReason + "test" + policyDenialMark([]string{"runtime"}, keys),
	}
}

func holdIgnored(entry *audit.ActionEntry, paths ...string) bool {
	return slices.Contains(PolicyHoldIgnoredFields(entry, paths).Ignored, "runtime")
}

// A path reaches a held copy through any link, to the folder, a folder below
// it, a file in it, a link of links, or a link above it. Each is resolved
// first, so each stays held; a copy the hold was not written for does not.
func TestPolicyHoldResolvesLinksBeforeComparingWithTheHeldCopy(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("links need privileges on Windows")
	}
	root := t.TempDir()
	held := filepath.Join(root, "held", "shared-name")
	admitted := filepath.Join(root, "admitted", "shared-name")
	for _, dir := range []string{filepath.Join(held, "nested"), filepath.Join(admitted, "nested")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, dir := range []string{held, admitted} {
		if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("---\nname: shared-name\n---\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	links := filepath.Join(root, "links")
	if err := os.MkdirAll(links, 0o700); err != nil {
		t.Fatal(err)
	}
	link := func(name, target string) string {
		t.Helper()
		path := filepath.Join(links, name)
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
		return path
	}
	entry := policyHoldEntryFor(held)
	protected := map[string]string{
		"the held folder":                 held,
		"a file of the held folder":       filepath.Join(held, "SKILL.md"),
		"a missing file of the held copy": filepath.Join(held, "not-written-yet.md"),
		"link to the held folder":         link("to-held", held),
		"link to a folder below it":       link("to-nested", filepath.Join(held, "nested")),
		"link to its file":                link("to-file", filepath.Join(held, "SKILL.md")),
		"link to a link to its file":      link("to-link", filepath.Join(links, "to-file")),
		"file below a link to the copy":   filepath.Join(links, "to-held", "SKILL.md"),
		"missing file below a deep link":  filepath.Join(links, "to-nested", "missing", "x.md"),
		"relative link to the held file":  link("relative", filepath.Join("..", "held", "shared-name", "SKILL.md")),
	}
	for label, path := range protected {
		if holdIgnored(entry, path) {
			t.Errorf("%s: the hold was ignored for %s", label, path)
		}
	}
	// Benign twin: the admitted copy of the name and links to it run.
	benign := map[string]string{
		"the admitted folder":       admitted,
		"a file of the admitted":    filepath.Join(admitted, "SKILL.md"),
		"a missing file of it":      filepath.Join(admitted, "not-written-yet.md"),
		"link to the admitted copy": link("to-admitted", admitted),
		"link to its file":          link("to-admitted-file", filepath.Join(admitted, "SKILL.md")),
	}
	for label, path := range benign {
		if !holdIgnored(entry, path) {
			t.Errorf("%s: the hold was kept for %s", label, path)
		}
	}
	// A path that cannot be resolved keeps the hold: a link to nowhere, a loop.
	dangling := link("dangling", filepath.Join(root, "nowhere"))
	loop := link("loop", filepath.Join(links, "loop"))
	for label, path := range map[string]string{"dangling link": dangling, "link loop": loop} {
		if holdIgnored(entry, path) {
			t.Errorf("%s: the hold was ignored for an unresolved path", label)
		}
	}
}

// A link that sits in a held copy is a protected path whatever it points to,
// and so is a link that passes through one; a hard link to a file of the held
// folder is the same file. The admitted copy of the name, a link to it and a
// hard link to its file run.
func TestPolicyHoldKeepsNamedLinksAndHardLinksOfTheHeldCopy(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("links need privileges on Windows")
	}
	root := t.TempDir()
	held := filepath.Join(root, "held", "shared-name")
	admitted := filepath.Join(root, "admitted", "shared-name")
	for _, dir := range []string{filepath.Join(held, "nested"), filepath.Join(admitted, "nested")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, file := range []string{
		filepath.Join(held, "SKILL.md"), filepath.Join(held, "nested", "deep.md"),
		filepath.Join(admitted, "SKILL.md"), filepath.Join(admitted, "nested", "deep.md"),
	} {
		if err := os.WriteFile(file, []byte("---\nname: shared-name\n---\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	links := filepath.Join(root, "links")
	if err := os.MkdirAll(links, 0o700); err != nil {
		t.Fatal(err)
	}
	symlink := func(path, target string) string {
		t.Helper()
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
		return path
	}
	hardlink := func(name, target string) string {
		t.Helper()
		path := filepath.Join(links, name)
		if err := os.Link(target, path); err != nil {
			t.Skipf("hard links unavailable: %v", err)
		}
		return path
	}
	outwardFile := symlink(filepath.Join(held, "outward-file"), filepath.Join(admitted, "SKILL.md"))
	outwardDir := symlink(filepath.Join(held, "nested", "outward-dir"), admitted)
	entry := policyHoldEntryFor(held)
	protected := map[string]string{
		"link in the held folder to an admitted file":    outwardFile,
		"link in a held subfolder to an admitted folder": outwardDir,
		"file below a link in the held folder":           filepath.Join(outwardDir, "SKILL.md"),
		"link outside to a link in the held folder":      symlink(filepath.Join(links, "via-link"), outwardFile),
		"link outside to a deep link in the held folder": symlink(filepath.Join(links, "via-deep-link"), filepath.Join(held, "nested", "outward-dir")),
		"hard link to the held file":                     hardlink("hard-file", filepath.Join(held, "SKILL.md")),
		"hard link to a file below the held folder":      hardlink("hard-deep", filepath.Join(held, "nested", "deep.md")),
		"link to a hard link to the held file":           symlink(filepath.Join(links, "to-hard"), filepath.Join(links, "hard-file")),
	}
	for label, path := range protected {
		if holdIgnored(entry, path) {
			t.Errorf("%s: the hold was ignored for %s", label, path)
		}
	}
	benign := map[string]string{
		"the admitted file":              filepath.Join(admitted, "SKILL.md"),
		"link to the admitted folder":    symlink(filepath.Join(links, "to-admitted"), admitted),
		"hard link to the admitted file": hardlink("hard-admitted", filepath.Join(admitted, "SKILL.md")),
		"a regular file elsewhere":       filepath.Join(root, "elsewhere.md"),
	}
	if err := os.WriteFile(benign["a regular file elsewhere"], []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	for label, path := range benign {
		if !holdIgnored(entry, path) {
			t.Errorf("%s: the hold was kept for %s", label, path)
		}
	}
}

// The strict tier holds the root owner whose rules allow a skill another
// connector denies. The tier is the one of the policy that decided the denial:
// a reload to strict that took effect after the watcher started holds the owner
// too.
func TestRootOwnerIsHeldWhenAReloadMovedItToTheStrictTier(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the quarantine store is made unwritable with a file")
	}
	w, started, evt := sharedRootDefaultDenyWatcher(t, false)
	live := *started
	live.Guardrail.RulePackDir = filepath.Join(t.TempDir(), "strict")
	if PolicyHoldStrict(started, "amp") || !PolicyHoldStrict(&live, "amp") {
		t.Fatal("test setup: the started config must be balanced and the live config strict")
	}
	w.SetConfigSource(func() *config.Config { return &live })
	if res := w.runAdmission(context.Background(), evt); res.Verdict != VerdictBlocked {
		t.Fatalf("admission = %+v, want blocked", res)
	}
	requireRuntimeHoldFor(t, w, true, "codex", "amp")
}

// A held copy this process cannot look at (a private parent folder) is
// present, unknown. It stays in the hold; a call that resolves elsewhere is
// reported with it, and a path through the private folder keeps the hold.
func TestPolicyHoldKeepsACopyThatCannotBeInspected(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs POSIX permissions as a non-root user")
	}
	root := t.TempDir()
	private := filepath.Join(root, "private-home")
	held := filepath.Join(private, "shared-name")
	admitted := filepath.Join(root, "admitted", "shared-name")
	for _, dir := range []string{held, admitted} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(held, alias); err != nil {
		t.Fatal(err)
	}
	entry := policyHoldEntryFor(held)
	if err := os.Chmod(private, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(private, 0o700) })
	if _, err := os.Lstat(held); err == nil {
		t.Skip("this test needs an unprivileged process")
	}
	_, key := parsePolicyHold(entry.Reason)
	if got := livePolicyCopies(key, ""); len(got) != 1 {
		t.Fatalf("live copies = %v, want the copy that cannot be inspected to stay", got)
	}
	scope := PolicyHoldIgnoredFields(entry, []string{admitted})
	if !slices.Contains(scope.Ignored, "runtime") || !slices.Equal(scope.Unknown, []string{held}) {
		t.Errorf("admitted copy: scope = %+v, want the hold ignored and the held copy reported unknown", scope)
	}
	for label, path := range map[string]string{"the held folder": held, "a link to it": alias, "a file in it": filepath.Join(held, "SKILL.md")} {
		if got := PolicyHoldIgnoredFields(entry, []string{path}); len(got.Ignored) != 0 {
			t.Errorf("%s: the hold was ignored (%+v) for a path through the private folder", label, got)
		}
	}
}

// A root owner whose own rules allow a skill that another connector denies
// runs it in the balanced tier; the denying connector stays held. The strict
// tier holds the owner too.
func TestRootOwnerThatAllowsTheSkillIsHeldOnlyInTheStrictTier(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the quarantine store is made unwritable with a file")
	}
	for _, tc := range []struct {
		name      string
		strict    bool
		wantOwner bool
	}{
		{"balanced", false, false},
		{"strict tier", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w, cfg, evt := sharedRootDefaultDenyWatcher(t, false)
			if tc.strict {
				cfg.Guardrail.RulePackDir = filepath.Join(t.TempDir(), "strict")
			}
			if res := w.runAdmission(context.Background(), evt); res.Verdict != VerdictBlocked {
				t.Fatalf("admission = %+v, want blocked", res)
			}
			pe := enforce.NewPolicyEngine(w.store)
			for connector, want := range map[string]bool{"codex": true, "amp": tc.wantOwner} {
				if disabled, err := pe.IsDisabledForConnector("skill", evt.Name, connector); err != nil || disabled != want {
					entry, _ := w.store.GetActionForConnector("skill", evt.Name, connector)
					t.Errorf("%s runtime disabled = %v (err %v), want %v; journal %+v", connector, disabled, err, want, entry)
				}
			}
		})
	}
}
