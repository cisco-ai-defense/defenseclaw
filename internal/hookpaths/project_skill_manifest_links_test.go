// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// manifestLinkProject makes home/project/.claude/skills as a plain folder
// and returns the project, the root and the verified-root facts a hook
// sends for it.
func manifestLinkProject(t *testing.T) (home, project, root string, facts map[string]string) {
	t.Helper()
	home = t.TempDir()
	project = filepath.Join(home, "project")
	root = filepath.Join(project, ".claude", "skills")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	return home, project, root, map[string]string{ProjectSkillRootVerifiedPrefix + root: "1"}
}

// A plain project skills root is verified as a folder, but a skill of it can
// carry a SKILL.md that is another file under that name. A call that selects
// that skill, by name or by any explicit source, turns the root unverified
// for the call and binds the selected folder, so the gateway refuses it
// (rel-1-0-9:GAP-0951). Private in-profile twins and ordinary skills stay
// verified.
func TestProjectSkillManifestLinkedOutsideTheProfileIsNotVerified(t *testing.T) {
	type build func(t *testing.T, home, root string) string // returns the skill folder
	outsideFile := func(t *testing.T) string {
		path := filepath.Join(t.TempDir(), "policy.md")
		if err := os.WriteFile(path, []byte("---\nname: sample\n---\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	cases := []struct {
		label string
		make  build
		bad   bool
	}{
		{"ordinary regular manifest", func(t *testing.T, _, root string) string {
			dir := filepath.Join(root, "sample")
			round6Skill(t, dir, "sample")
			return dir
		}, false},
		{"symbolic link to a file outside the profile", func(t *testing.T, _, root string) string {
			dir := filepath.Join(root, "sample")
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outsideFile(t), filepath.Join(dir, "SKILL.md")); err != nil {
				t.Skipf("link unavailable: %v", err)
			}
			return dir
		}, true},
		{"hard link to a file outside the profile", func(t *testing.T, _, root string) string {
			dir := filepath.Join(root, "sample")
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Link(outsideFile(t), filepath.Join(dir, "SKILL.md")); err != nil {
				t.Skipf("hard link unavailable: %v", err)
			}
			return dir
		}, true},
		{"skill folder that is a link to a folder outside the profile", func(t *testing.T, _, root string) string {
			outside := filepath.Join(t.TempDir(), "sample")
			round6Skill(t, outside, "sample")
			dir := filepath.Join(root, "sample")
			if err := os.Symlink(outside, dir); err != nil {
				t.Skipf("link unavailable: %v", err)
			}
			return dir
		}, true},
		{"symbolic link to the caller private file in the profile", func(t *testing.T, home, root string) string {
			private := filepath.Join(home, ".claude", "skills", "sample")
			round6Skill(t, private, "sample")
			dir := filepath.Join(root, "sample")
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join(private, "SKILL.md"), filepath.Join(dir, "SKILL.md")); err != nil {
				t.Skipf("link unavailable: %v", err)
			}
			return dir
		}, false},
		{"skill folder that is a link to a private folder in the profile", func(t *testing.T, home, root string) string {
			private := filepath.Join(home, "elsewhere", "sample")
			round6Skill(t, private, "sample")
			dir := filepath.Join(root, "sample")
			if err := os.Symlink(private, dir); err != nil {
				t.Skipf("link unavailable: %v", err)
			}
			return dir
		}, false},
		{"folder without a manifest", func(t *testing.T, _, root string) string {
			dir := filepath.Join(root, "sample")
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			return dir
		}, false},
	}
	selections := map[string]func(dir string) map[string]any{
		"name":              func(string) map[string]any { return map[string]any{"skill": "sample"} },
		"skill_path folder": func(dir string) map[string]any { return map[string]any{"skill": "sample", "skill_path": dir} },
		"skill_path manifest": func(dir string) map[string]any {
			return map[string]any{"skill": "sample", "skill_path": filepath.Join(dir, "SKILL.md")}
		},
	}
	for _, tc := range cases {
		for form, selection := range selections {
			t.Run(tc.label+"/"+form, func(t *testing.T) {
				home, project, root, facts := manifestLinkProject(t)
				dir := tc.make(t, home, root)
				// A second, ordinary skill of the same root.
				round6Skill(t, filepath.Join(root, "other"), "other")
				args, _ := json.Marshal(selection(dir))
				addProjectSkillSelectedFacts(facts, nil, args, home, project)
				unverified := facts[ProjectSkillRootUnverifiedPrefix+root]
				_, verified := facts[ProjectSkillRootVerifiedPrefix+root]
				selected := round6Selected(facts)
				if tc.bad {
					if unverified != ProjectSkillManifestLinked || verified || len(selected) != 1 || selected[0] != dir {
						t.Fatalf("linked manifest: unverified=%q verified=%v selected=%v, want %s bound to %s",
							unverified, verified, selected, ProjectSkillManifestLinked, dir)
					}
					return
				}
				if unverified != "" || !verified || len(selected) != 0 {
					t.Fatalf("benign skill: unverified=%q verified=%v selected=%v, want the root verified", unverified, verified, selected)
				}
			})
		}
	}
	t.Run("another skill of the root stays verified", func(t *testing.T) {
		home, project, root, facts := manifestLinkProject(t)
		dir := filepath.Join(root, "sample")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outsideFile(t), filepath.Join(dir, "SKILL.md")); err != nil {
			t.Skipf("link unavailable: %v", err)
		}
		round6Skill(t, filepath.Join(root, "other"), "other")
		args, _ := json.Marshal(map[string]any{"skill": "other"})
		addProjectSkillSelectedFacts(facts, nil, args, home, project)
		if _, verified := facts[ProjectSkillRootVerifiedPrefix+root]; !verified || len(facts) != 1 {
			t.Fatalf("a call for the ordinary skill: facts %v, want the root verified alone", facts)
		}
	})
	t.Run("codex name selection", func(t *testing.T) {
		home, project, root, facts := manifestLinkProject(t)
		dir := filepath.Join(root, "sample")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outsideFile(t), filepath.Join(dir, "SKILL.md")); err != nil {
			t.Skipf("link unavailable: %v", err)
		}
		markLinkedProjectSkillManifests(facts, "sample", nil, home, project)
		if facts[ProjectSkillRootUnverifiedPrefix+root] != ProjectSkillManifestLinked {
			t.Fatalf("facts %v, want the root unverified as %s", facts, ProjectSkillManifestLinked)
		}
	})
}

// A project skill is also invoked by the name its SKILL.md declares, whatever
// the folder is called. A manifest that is a link is read as the agent reads
// it, so the declared-name call binds that folder like a call by folder name,
// and the private in-profile twin stays verified (rel-1-0-9:GAP-0951).
func TestProjectSkillManifestLinkSelectedByDeclaredName(t *testing.T) {
	cases := []struct {
		label string
		link  func(t *testing.T, home string) string // the file the manifest links to
		bad   bool
	}{
		{"link to a file outside the profile", func(t *testing.T, _ string) string {
			path := filepath.Join(t.TempDir(), "policy.md")
			if err := os.WriteFile(path, []byte("---\nname: sample\n---\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			return path
		}, true},
		{"link to the caller private file in the profile", func(t *testing.T, home string) string {
			private := filepath.Join(home, "private", "sample")
			round6Skill(t, private, "sample")
			return filepath.Join(private, "SKILL.md")
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.label, func(t *testing.T) {
			home, project, root, facts := manifestLinkProject(t)
			dir := filepath.Join(root, "folder")
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(tc.link(t, home), filepath.Join(dir, "SKILL.md")); err != nil {
				t.Skipf("link unavailable: %v", err)
			}
			round6Skill(t, filepath.Join(root, "other"), "other")
			args, _ := json.Marshal(map[string]any{"skill": "sample"})
			addProjectSkillSelectedFacts(facts, nil, args, home, project)
			unverified := facts[ProjectSkillRootUnverifiedPrefix+root]
			_, verified := facts[ProjectSkillRootVerifiedPrefix+root]
			selected := round6Selected(facts)
			if tc.bad {
				if unverified != ProjectSkillManifestLinked || verified || len(selected) != 1 || selected[0] != dir {
					t.Fatalf("declared-name call: unverified=%q verified=%v selected=%v, want %s bound to %s",
						unverified, verified, selected, ProjectSkillManifestLinked, dir)
				}
				return
			}
			if unverified != "" || !verified || len(selected) != 0 {
				t.Fatalf("private twin: unverified=%q verified=%v selected=%v, want the root verified", unverified, verified, selected)
			}
		})
	}
}

// A manifest that cannot be resolved makes the root unverified as
// unreadable, not as a link, so the refusal names what went wrong.
func TestProjectSkillManifestUnresolvableKeepsTheUnreadableReason(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("a self link is not a loop the same way on Windows")
	}
	home, project, root, facts := manifestLinkProject(t)
	dir := filepath.Join(root, "sample")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("SKILL.md", filepath.Join(dir, "SKILL.md")); err != nil {
		t.Skipf("link unavailable: %v", err)
	}
	args, _ := json.Marshal(map[string]any{"skill": "sample", "skill_path": dir})
	addProjectSkillSelectedFacts(facts, nil, args, home, project)
	if got := facts[ProjectSkillRootUnverifiedPrefix+root]; got != ProjectSkillRootUnreadable {
		t.Fatalf("facts %v, want the root unverified as %s", facts, ProjectSkillRootUnreadable)
	}
}

// A Skill call that gives only the name selects the folder of that name even
// when its SKILL.md is a link loop that cannot be resolved: the root turns
// unverified as unreadable and the folder is bound, whether the call is a
// hook Skill call or the Codex prompt route, which share the two helpers.
// A manifest that is absent, and an ordinary skill, keep the root verified
// (rel-1-0-9:GAP-0987).
func TestProjectSkillManifestLoopSelectedByNameOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("a link loop is not the same error on Windows")
	}
	loop := func(t *testing.T, _, dir string) {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("loop2.md", filepath.Join(dir, "SKILL.md")); err != nil {
			t.Skipf("link unavailable: %v", err)
		}
		if err := os.Symlink("SKILL.md", filepath.Join(dir, "loop2.md")); err != nil {
			t.Skipf("link unavailable: %v", err)
		}
	}
	cases := []struct {
		label string
		make  func(t *testing.T, home, dir string)
		bad   bool
	}{
		{"two-link loop", loop, true},
		{"self link", func(t *testing.T, _, dir string) {
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("SKILL.md", filepath.Join(dir, "SKILL.md")); err != nil {
				t.Skipf("link unavailable: %v", err)
			}
		}, true},
		{"manifest absent", func(t *testing.T, _, dir string) {
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
		}, false},
		{"dangling link", func(t *testing.T, _, dir string) {
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("missing.md", filepath.Join(dir, "SKILL.md")); err != nil {
				t.Skipf("link unavailable: %v", err)
			}
		}, false},
		{"name is a plain file", func(t *testing.T, _, dir string) {
			if err := os.WriteFile(dir, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
		}, false},
		{"ordinary private skill", func(t *testing.T, _, dir string) { round6Skill(t, dir, "sample") }, false},
	}
	for _, tc := range cases {
		t.Run(tc.label, func(t *testing.T) {
			home, project, root, facts := manifestLinkProject(t)
			dir := filepath.Join(root, "sample")
			tc.make(t, home, dir)

			folders := projectSkillSelectedFolders(root, "sample")
			if tc.bad && (len(folders) != 1 || folders[0] != dir) {
				t.Fatalf("selected folders %v, want %s", folders, dir)
			}

			// The Codex prompt route marks and binds with the same helpers and no source.
			codex := map[string]string{ProjectSkillRootVerifiedPrefix + root: "1"}
			markLinkedProjectSkillManifests(codex, "sample", nil, home, project)
			if got := codex[ProjectSkillRootUnverifiedPrefix+root]; (got == ProjectSkillRootUnreadable) != tc.bad {
				t.Fatalf("codex name-only: %v", codex)
			}

			args, _ := json.Marshal(map[string]any{"skill": "sample"})
			addProjectSkillSelectedFacts(facts, nil, args, home, project)
			_, verified := facts[ProjectSkillRootVerifiedPrefix+root]
			unverified := facts[ProjectSkillRootUnverifiedPrefix+root]
			_, bound := facts[ProjectSkillSelectedPrefix+dir]
			if tc.bad {
				if unverified != ProjectSkillRootUnreadable || verified || !bound {
					t.Fatalf("name-only call: unverified=%q verified=%v bound=%v in %v, want %s with %s bound",
						unverified, verified, bound, facts, ProjectSkillRootUnreadable, dir)
				}
				return
			}
			if unverified != "" || !verified || bound {
				t.Fatalf("benign twin: unverified=%q verified=%v bound=%v in %v, want the root verified", unverified, verified, bound, facts)
			}
		})
	}
}

// A SKILL.md that is a chain of symbolic links to an otherwise private file
// is judged as the system resolves it: past the 40 links Linux follows the
// agent cannot load it, so the root is unverified as unreadable and the
// folder is bound, on the hook name-only call, the Codex prompt route and
// the explicit-path call alike, even though the user-space link walk would
// reach the file. A chain within the limit stays verified
// (rel-1-0-9:GAP-0987).
func TestProjectSkillManifestChainPastTheSystemLimitIsUnreadable(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the link limit this test relies on is the Linux one")
	}
	calls := map[string]func(dir string) map[string]any{
		"name only":  func(string) map[string]any { return map[string]any{"skill": "sample"} },
		"skill_path": func(dir string) map[string]any { return map[string]any{"skill": "sample", "skill_path": dir} },
	}
	for _, tc := range []struct {
		links int
		bad   bool
	}{{2, false}, {40, false}, {41, true}, {43, true}} {
		for label, call := range calls {
			t.Run(fmt.Sprintf("%d links %s", tc.links, label), func(t *testing.T) {
				home, project, root, facts := manifestLinkProject(t)
				dir := filepath.Join(root, "sample")
				if err := os.MkdirAll(dir, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, "real.md"), []byte("---\nname: sample\n---\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				// SKILL.md -> hop1 -> ... -> real.md, tc.links links in all.
				for i := tc.links; i >= 1; i-- {
					from := "SKILL.md"
					if i > 1 {
						from = fmt.Sprintf("hop%d.md", i-1)
					}
					to := "real.md"
					if i < tc.links {
						to = fmt.Sprintf("hop%d.md", i)
					}
					if err := os.Symlink(to, filepath.Join(dir, from)); err != nil {
						t.Skipf("link unavailable: %v", err)
					}
				}
				if got := projectSkillManifestFinding(home, dir); (got == ProjectSkillRootUnreadable) != tc.bad {
					t.Fatalf("manifest finding %q, want unreadable=%v", got, tc.bad)
				}

				codex := map[string]string{ProjectSkillRootVerifiedPrefix + root: "1"}
				if label == "name only" {
					markLinkedProjectSkillManifests(codex, "sample", nil, home, project)
					if got := codex[ProjectSkillRootUnverifiedPrefix+root]; (got == ProjectSkillRootUnreadable) != tc.bad {
						t.Fatalf("codex name-only: %v", codex)
					}
				}

				args, _ := json.Marshal(call(dir))
				addProjectSkillSelectedFacts(facts, nil, args, home, project)
				_, verified := facts[ProjectSkillRootVerifiedPrefix+root]
				unverified := facts[ProjectSkillRootUnverifiedPrefix+root]
				_, bound := facts[ProjectSkillSelectedPrefix+dir]
				if tc.bad {
					if unverified != ProjectSkillRootUnreadable || verified || !bound {
						t.Fatalf("unverified=%q verified=%v bound=%v in %v, want %s with %s bound",
							unverified, verified, bound, facts, ProjectSkillRootUnreadable, dir)
					}
					return
				}
				if unverified != "" || !verified || bound {
					t.Fatalf("within the limit: unverified=%q verified=%v bound=%v in %v, want the root verified",
						unverified, verified, bound, facts)
				}
			})
		}
	}
}

// A project skill folder that is itself a chain of folder links to an
// ordinary private skill is judged as the system resolves SKILL.md through
// it: past the 40 links Linux follows the agent cannot load it, so the root
// is unverified as unreadable and the folder is bound, whether the call
// names only the skill (hook or Codex prompt route) or gives its path. A
// chain within the limit, and an absent folder, stay verified
// (rel-1-0-9:GAP-0987).
func TestProjectSkillFolderLinkChainPastTheSystemLimitIsUnreadable(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the link limit this test relies on is the Linux one")
	}
	calls := map[string]func(dir string) map[string]any{
		"name only":  func(string) map[string]any { return map[string]any{"skill": "sample"} },
		"skill_path": func(dir string) map[string]any { return map[string]any{"skill": "sample", "skill_path": dir} },
	}
	for _, tc := range []struct {
		links int // folder links in the path of SKILL.md; 0 leaves the folder absent
		bad   bool
	}{{0, false}, {1, false}, {39, false}, {40, false}, {41, true}, {42, true}} {
		for label, call := range calls {
			t.Run(fmt.Sprintf("%d links %s", tc.links, label), func(t *testing.T) {
				home, project, root, facts := manifestLinkProject(t)
				dir := filepath.Join(root, "sample")
				if tc.links > 0 {
					real := filepath.Join(home, "store", "sample")
					round6Skill(t, real, "sample")
					hops := filepath.Join(home, "hops")
					if err := os.MkdirAll(hops, 0o700); err != nil {
						t.Fatal(err)
					}
					// dir -> hop1 -> ... -> real, tc.links links in all.
					for i := tc.links; i >= 1; i-- {
						from := dir
						if i > 1 {
							from = filepath.Join(hops, fmt.Sprintf("hop%d", i-1))
						}
						to := real
						if i < tc.links {
							to = filepath.Join(hops, fmt.Sprintf("hop%d", i))
						}
						if err := os.Symlink(to, from); err != nil {
							t.Skipf("link unavailable: %v", err)
						}
					}
				}
				if got := projectSkillManifestFinding(home, dir); (got == ProjectSkillRootUnreadable) != tc.bad {
					t.Fatalf("manifest finding %q, want unreadable=%v", got, tc.bad)
				}

				if label == "name only" {
					codex := map[string]string{ProjectSkillRootVerifiedPrefix + root: "1"}
					markLinkedProjectSkillManifests(codex, "sample", nil, home, project)
					if got := codex[ProjectSkillRootUnverifiedPrefix+root]; (got == ProjectSkillRootUnreadable) != tc.bad {
						t.Fatalf("codex name-only: %v", codex)
					}
				}

				args, _ := json.Marshal(call(dir))
				addProjectSkillSelectedFacts(facts, nil, args, home, project)
				_, verified := facts[ProjectSkillRootVerifiedPrefix+root]
				unverified := facts[ProjectSkillRootUnverifiedPrefix+root]
				_, bound := facts[ProjectSkillSelectedPrefix+dir]
				if tc.bad {
					if unverified != ProjectSkillRootUnreadable || verified || !bound {
						t.Fatalf("unverified=%q verified=%v bound=%v in %v, want %s with %s bound",
							unverified, verified, bound, facts, ProjectSkillRootUnreadable, dir)
					}
					return
				}
				if unverified != "" || !verified || bound {
					t.Fatalf("within the limit: unverified=%q verified=%v bound=%v in %v, want the root verified",
						unverified, verified, bound, facts)
				}
			})
		}
	}
}
