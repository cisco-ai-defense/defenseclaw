// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// Run these with the slow-share overlay in testdata to model a share whose
// root probe is pending while its files are readable through another name.
// A direct read of the files supplies the base verdict.
func TestGAP0482ReviewSlowShareHardLink(t *testing.T) {
	for _, placement := range []string{"both", "target", "home"} {
		t.Run(placement, func(t *testing.T) {
			root := t.TempDir()
			home := filepath.Join(root, "home")
			project := filepath.Join(root, "project")
			for _, dir := range []string{filepath.Join(home, ".ssh"), project} {
				if err := os.MkdirAll(dir, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			keys := filepath.Join(home, ".ssh", "authorized_keys")
			if err := os.WriteFile(keys, []byte("placeholder\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			alias := filepath.Join(project, "ordinary.txt")
			if err := os.Link(keys, alias); err != nil {
				t.Skipf("hard links unavailable: %v", err)
			}
			switch placement {
			case "both":
				t.Setenv("R482_FAKE_SHARE", root)
			case "target":
				t.Setenv("R482_FAKE_SHARE", project)
			case "home":
				t.Setenv("R482_FAKE_SHARE", home)
			}
			t.Setenv("HOME", home)
			t.Setenv("USERPROFILE", home)
			payload := mustJSON(t, map[string]any{
				"session_id": "gap0482-slow-hardlink", "hook_event_name": "PreToolUse",
				"tool_name": "Bash", "tool_use_id": "toolu_gap0482_slow_hardlink",
				"cwd": project, "permission_mode": "default",
				"tool_input": map[string]any{"command": "echo marker >> ordinary.txt"},
			})
			if got := gap0482ProfileVerdict(t, payload, "strict"); got != "block" {
				t.Fatalf("strict hard-link alias = %s, want block", got)
			}
			if got := gap0482ProfileVerdict(t, payload, "default"); got != "block" {
				t.Fatalf("default hard-link alias = %s, want block", got)
			}
		})
	}
}

func TestGAP0482ReviewSlowShareOrdinaryWrite(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	project := filepath.Join(root, "project")
	for _, dir := range []string{filepath.Join(home, ".ssh"), project} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(home, ".ssh", "authorized_keys"), []byte("placeholder\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "ordinary.txt"), []byte("notes\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("R482_FAKE_SHARE", project)
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	payload := mustJSON(t, map[string]any{
		"session_id": "gap0482-slow-ordinary", "hook_event_name": "PreToolUse",
		"tool_name": "Bash", "tool_use_id": "toolu_gap0482_slow_ordinary",
		"cwd": project, "permission_mode": "default",
		"tool_input": map[string]any{"command": "echo marker >> ordinary.txt"},
	})
	if got := r106PerUserVerdict(t, "claudecode", payload, ""); got != "allow" {
		t.Fatalf("ordinary write on an answering share = %s, want allow", got)
	}
}

func TestGAP0482ReviewSlowHomeLocalPythonReassignment(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	project := filepath.Join(root, "project")
	ordinary := filepath.Join(project, "ordinary.txt")
	for _, dir := range []string{filepath.Join(home, ".ssh"), project} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(home, ".ssh", "authorized_keys"), []byte("placeholder\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("R482_FAKE_SHARE", home)
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	code := `from pathlib import Path; p = Path.home() / ".ssh" / "authorized_keys"; p = Path(` + strconv.Quote(filepath.ToSlash(ordinary)) + `); p.write_text("x")`
	payload := mustJSON(t, map[string]any{
		"session_id": "gap0482-slow-home-local", "hook_event_name": "PreToolUse",
		"tool_name": "Bash", "tool_use_id": "toolu_gap0482_slow_home_local",
		"cwd": project, "permission_mode": "default",
		"tool_input": map[string]any{"command": "python3 -c '" + code + "'"},
	})
	if got := r106PerUserVerdict(t, "claudecode", payload, ""); got != "allow" {
		t.Fatalf("local Python reassignment = %s, want allow", got)
	}
	if got := gap0482ProfileVerdict(t, payload, "strict"); got != "allow" {
		t.Fatalf("strict local Python reassignment = %s, want allow", got)
	}
}

func TestGAP0482ReviewSlowShareSymlink(t *testing.T) {
	for _, row := range []struct {
		name                              string
		keysPresent, relative, parentLink bool
	}{{"existing", true, false, false}, {"missing-final-file", false, false, false},
		{"missing-relative-link", false, true, false}, {"missing-parent-link", false, false, true}} {
		t.Run(row.name, func(t *testing.T) {
			for _, placement := range []string{"both", "target", "home"} {
				t.Run(placement, func(t *testing.T) {
					root := t.TempDir()
					home := filepath.Join(root, "home")
					project := filepath.Join(root, "project")
					for _, dir := range []string{filepath.Join(home, ".ssh"), project} {
						if err := os.MkdirAll(dir, 0o700); err != nil {
							t.Fatal(err)
						}
					}
					keys := filepath.Join(home, ".ssh", "authorized_keys")
					if row.keysPresent {
						if err := os.WriteFile(keys, []byte("placeholder\n"), 0o600); err != nil {
							t.Fatal(err)
						}
					}
					alias := filepath.Join(project, "ordinary.txt")
					link := keys
					if row.relative {
						var err error
						link, err = filepath.Rel(project, keys)
						if err != nil {
							t.Fatal(err)
						}
					}
					if row.parentLink {
						alias = filepath.Join(project, "linked")
						link = filepath.Dir(keys)
					}
					if err := os.Symlink(link, alias); err != nil {
						t.Skipf("symlinks unavailable: %v", err)
					}
					switch placement {
					case "both":
						t.Setenv("R482_FAKE_SHARE", root)
					case "target":
						t.Setenv("R482_FAKE_SHARE", project)
					case "home":
						t.Setenv("R482_FAKE_SHARE", home)
					}
					t.Setenv("HOME", home)
					t.Setenv("USERPROFILE", home)
					command := "echo marker >> ordinary.txt"
					if row.parentLink {
						command = "echo marker >> linked/authorized_keys"
					}
					payload := mustJSON(t, map[string]any{
						"session_id": "gap0482-slow-symlink", "hook_event_name": "PreToolUse",
						"tool_name": "Bash", "tool_use_id": "toolu_gap0482_slow_symlink",
						"cwd": project, "permission_mode": "default",
						"tool_input": map[string]any{"command": command},
					})
					if got := gap0482ProfileVerdict(t, payload, "strict"); got != "block" {
						t.Fatalf("strict symlink alias = %s, want block", got)
					}
					if got := gap0482ProfileVerdict(t, payload, "default"); got != "block" {
						t.Fatalf("default symlink alias = %s, want block", got)
					}
				})
			}
		})
	}
}

// The slow-share overlay delays each reachable file read while its root
// probe is pending. A known chain must retain the protected final name.
func TestGAP0482SlowShareLinkChain(t *testing.T) {
	for _, row := range []struct {
		name     string
		depth    int
		missing  bool
		relative bool
		ordinary bool
	}{
		{"direct-missing", 1, true, false, false},
		{"two-hop-missing", 2, true, false, false},
		{"two-hop-relative-missing", 2, true, true, false},
		{"three-hop-missing", 3, true, false, false},
		{"eight-hop-missing", 8, true, false, false},
		{"two-hop-existing", 2, false, false, false},
		{"ordinary-two-hop", 2, false, false, true},
	} {
		t.Run(row.name, func(t *testing.T) {
			root := t.TempDir()
			home := filepath.Join(root, "home")
			project := filepath.Join(root, "project")
			for _, dir := range []string{filepath.Join(home, ".ssh"), project} {
				if err := os.MkdirAll(dir, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			keys := filepath.Join(home, ".ssh", "authorized_keys")
			if row.ordinary {
				keys = filepath.Join(project, "notes.txt")
			}
			if !row.missing {
				if err := os.WriteFile(keys, []byte("placeholder\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			names := make([]string, row.depth)
			names[0] = filepath.Join(project, "ordinary.txt")
			for i := 1; i < len(names); i++ {
				names[i] = filepath.Join(project, "step"+strconv.Itoa(i)+".txt")
			}
			for i := 0; i < row.depth; i++ {
				destination := keys
				if i+1 < row.depth {
					destination = names[i+1]
				}
				if row.relative {
					var err error
					destination, err = filepath.Rel(project, destination)
					if err != nil {
						t.Fatal(err)
					}
				}
				if err := os.Symlink(destination, names[i]); err != nil {
					t.Skipf("symlink unavailable: %v", err)
				}
			}
			t.Setenv("R482_FAKE_SHARE", project)
			t.Setenv("R482_FAKE_SHARE_DELAY", "1")
			t.Setenv("HOME", home)
			t.Setenv("USERPROFILE", home)
			payload := mustJSON(t, map[string]any{
				"session_id": "gap0482-link-chain", "hook_event_name": "PreToolUse",
				"tool_name": "Bash", "tool_use_id": "toolu_gap0482_link_chain",
				"cwd": project, "permission_mode": "default",
				"tool_input": map[string]any{"command": "echo marker >> ordinary.txt"},
			})
			for _, profile := range []string{"default", "strict"} {
				want := "block"
				if row.ordinary {
					want = "allow"
				}
				if got := gap0482ProfileVerdict(t, payload, profile); got != want {
					t.Errorf("%s linked file = %s, want %s", profile, got, want)
				}
			}
		})
	}
}

func TestGAP0482KnownAndOrdinaryShareLinks(t *testing.T) {
	for _, row := range []struct {
		name      string
		depth     int
		parent    bool
		protected bool
		slow80    bool
	}{
		{"ordinary-parent-2", 2, true, false, false},
		{"ordinary-parent-2-selective-slow", 2, true, false, false},
		{"ordinary-parent-20", 20, true, false, false},
		{"protected-parent-20", 20, true, true, false},
		{"protected-file-link-80ms", 1, false, true, true},
		{"protected-hard-link-80ms", 0, false, true, true},
		{"protected-file-link-120ms", 1, false, true, false},
		{"protected-hard-link-120ms", 0, false, true, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			root := t.TempDir()
			home, project := filepath.Join(root, "home"), filepath.Join(root, "project")
			ordinaryDir := filepath.Join(root, "ordinary-dir")
			for _, dir := range []string{filepath.Join(home, ".ssh"), project, ordinaryDir} {
				if err := os.MkdirAll(dir, 0700); err != nil {
					t.Fatal(err)
				}
			}
			keys := filepath.Join(home, ".ssh", "authorized_keys")
			if err := os.WriteFile(keys, []byte("placeholder\n"), 0600); err != nil {
				t.Fatal(err)
			}
			ordinary := filepath.Join(ordinaryDir, "ordinary.txt")
			if err := os.WriteFile(ordinary, []byte("notes\n"), 0600); err != nil {
				t.Fatal(err)
			}
			target := ""
			if row.parent {
				for i := row.depth - 1; i >= 0; i-- {
					name := filepath.Join(project, "p"+strconv.Itoa(i))
					destination := filepath.Join(project, "p"+strconv.Itoa(i+1))
					if i == row.depth-1 {
						destination = ordinaryDir
						if row.protected {
							destination = filepath.Join(home, ".ssh")
						}
					}
					if err := os.Symlink(destination, name); err != nil {
						t.Skipf("symlink unavailable: %v", err)
					}
				}
				basename := "ordinary.txt"
				if row.protected {
					basename = "authorized_keys"
				}
				target = filepath.Join(project, "p0", basename)
				t.Setenv("R482_DELAY_TARGET", target)
				t.Setenv("R482_FAKE_SHARE_DELAY", "1")
				if row.name == "ordinary-parent-2-selective-slow" {
					t.Setenv("R482_SLOW_STEP", filepath.Join(project, "p1"))
				}
			} else {
				target = filepath.Join(project, "ordinary.txt")
				var err error
				if row.depth == 0 {
					err = os.Link(keys, target)
				} else {
					err = os.Symlink(keys, target)
				}
				if err != nil {
					t.Skipf("link unavailable: %v", err)
				}
				if row.slow80 {
					t.Setenv("R482_FAKE_SHARE_DELAY80", "1")
				} else {
					t.Setenv("R482_FAKE_SHARE_DELAY120", "1")
				}
			}
			t.Setenv("R482_FAKE_SHARE", project)
			t.Setenv("HOME", home)
			t.Setenv("USERPROFILE", home)
			payload := mustJSON(t, map[string]any{
				"session_id": "g288-near", "hook_event_name": "PreToolUse", "tool_name": "Bash",
				"tool_use_id": "toolu_g288_near", "cwd": project, "permission_mode": "default",
				"tool_input": map[string]any{"command": "echo marker >> " + filepath.ToSlash(target)},
			})
			started := time.Now()
			got := gap0482ProfileVerdict(t, payload, "default")
			t.Logf("default verdict=%s elapsed=%v", got, time.Since(started))
			want := "allow"
			if row.protected {
				want = "block"
			}
			if got != want {
				t.Errorf("default verdict=%s, want %s", got, want)
			}
		})
	}
}

func TestGAP0482PythonHardLinkSlowShare(t *testing.T) {
	root := t.TempDir()
	home, project := filepath.Join(root, "home"), filepath.Join(root, "project")
	for _, dir := range []string{filepath.Join(home, ".ssh"), project} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	if err := os.WriteFile(keys, []byte("placeholder\n"), 0600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(project, "linked.txt")
	if err := os.Link(keys, alias); err != nil {
		t.Skipf("hardlink unavailable: %v", err)
	}
	t.Setenv("R482_FAKE_SHARE", project)
	t.Setenv("R482_FAKE_SHARE_DELAY80", "1")
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	code := `from pathlib import Path; p = Path.home() / '.ssh' / 'authorized_keys'; p = Path('linked.txt'); p.write_text('hello')`
	payload := mustJSON(t, map[string]any{
		"session_id": "g288-python-hardlink", "hook_event_name": "PreToolUse", "tool_name": "Bash",
		"tool_use_id": "toolu_g288_python_hardlink", "cwd": project, "permission_mode": "default",
		"tool_input": map[string]any{"command": "python3 -c " + strconv.Quote(code)},
	})
	got := gap0482ProfileVerdict(t, payload, "default")
	t.Logf("default verdict=%s", got)
	if got != "block" {
		t.Errorf("protected hardlink allowed")
	}
}

func TestGAP0482NestedSlowShareBudget(t *testing.T) {
	root := t.TempDir()
	home, project := filepath.Join(root, "home"), filepath.Join(root, "project")
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0700); err != nil {
		t.Fatal(err)
	}
	dir := project
	for i := 0; i < 16; i++ {
		dir = filepath.Join(dir, "nested"+strconv.Itoa(i))
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	target := filepath.Join(dir, "ordinary.txt")
	if err := os.WriteFile(target, []byte("notes\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("R482_FAKE_SHARE", project)
	t.Setenv("R482_FAKE_SHARE_DELAY", "1")
	t.Setenv("R482_DELAY_TARGET", target)
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	payload := mustJSON(t, map[string]any{
		"session_id": "g288-nested", "hook_event_name": "PreToolUse", "tool_name": "Bash",
		"tool_use_id": "toolu_g288_nested", "cwd": project, "permission_mode": "default",
		"tool_input": map[string]any{"command": "echo marker >> " + filepath.ToSlash(target)},
	})
	start := time.Now()
	got := gap0482ProfileVerdict(t, payload, "default")
	elapsed := time.Since(start)
	t.Logf("default verdict=%s elapsed=%v", got, elapsed)
	if got != "allow" {
		t.Errorf("ordinary nested share write blocked")
	}
	if elapsed >= time.Second {
		t.Errorf("ordinary nested share answer exceeded one second: %v", elapsed)
	}
}
