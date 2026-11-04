//go:build darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// enableTestSelfRepair lets the unprivileged test process repair, stamping
// the test user instead of root:wheel.
func enableTestSelfRepair(t *testing.T) {
	t.Helper()
	restore := OverrideSelfRepairForTesting(UnixOwnership{UID: uint32(os.Getuid()), GID: uint32(os.Getgid())})
	t.Cleanup(restore)
}

func markerCount(lines []string, marker string) int {
	count := 0
	for _, line := range lines {
		if strings.HasPrefix(line, marker+" ") {
			count++
		}
	}
	return count
}

func TestRepairOwnedObjectDisabledWithoutRootOrOverride(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("runs as root")
	}
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("x"), 0o666); err != nil {
		t.Fatal(err)
	}
	mustChmod(t, path, 0o666)
	result := RepairOwnedObject(OwnedObject{Path: path, Kind: ObjectConfigFile})
	if result.Outcome != CanonicalUnsupported {
		t.Fatalf("outcome = %s, want unsupported", result.Outcome)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o666 {
		t.Fatalf("a disabled repair changed the mode to %04o", info.Mode().Perm())
	}
}

func TestRepairOwnedObjectRepairsEveryDriftClass(t *testing.T) {
	type drift struct {
		name     string
		apply    func(t *testing.T, path string)
		repaired bool
	}
	drifts := []drift{
		{name: "group write", apply: func(t *testing.T, p string) { mustChmod(t, p, 0o660) }, repaired: true},
		{name: "other write", apply: func(t *testing.T, p string) { mustChmod(t, p, 0o646) }, repaired: true},
		{name: "explicit write ACL", apply: func(t *testing.T, p string) { addDarwinACL(t, p, "everyone allow write,append") }, repaired: true},
		{name: "extra read ACL", apply: func(t *testing.T, p string) { addDarwinACL(t, p, "everyone allow read") }, repaired: true},
		{name: "uchg", apply: func(t *testing.T, p string) { mustChflags(t, p, "uchg") }, repaired: true},
		{name: "uappnd", apply: func(t *testing.T, p string) { mustChflags(t, p, "uappnd") }, repaired: true},
		{name: "hidden", apply: func(t *testing.T, p string) { mustChflags(t, p, "hidden") }},
		{name: "tighter mode", apply: func(t *testing.T, p string) {
			info, _ := os.Stat(p)
			mustChmod(t, p, info.Mode().Perm()&0o700)
		}},
	}
	for _, kind := range []ObjectKind{ObjectConfigFile, ObjectRuntimeDirectory} {
		for _, d := range drifts {
			t.Run(string(kind)+"/"+d.name, func(t *testing.T) {
				enableTestSelfRepair(t)
				events := captureResilienceEvents(t)
				path := filepath.Join(t.TempDir(), "object")
				if kind.Directory() {
					if err := os.Mkdir(path, 0o750); err != nil {
						t.Fatal(err)
					}
					mustChmod(t, path, 0o750)
				} else {
					if err := os.WriteFile(path, []byte("x"), 0o640); err != nil {
						t.Fatal(err)
					}
					mustChmod(t, path, 0o640)
				}
				t.Cleanup(func() { _ = exec.Command("/usr/bin/chflags", "nouchg,nouappnd", path).Run() })
				d.apply(t, path)

				result := RepairOwnedObject(OwnedObject{Path: path, Kind: kind})
				want := CanonicalOK
				if d.repaired {
					want = CanonicalRepaired
				}
				if result.Outcome != want {
					t.Fatalf("outcome = %s, want %s (drift %v, repair error %q)", result.Outcome, want, result.Drift, result.RepairError)
				}
				if again, _ := AssessCanonical(path, kind, selfRepairOptions(0)); again.Outcome != CanonicalOK {
					t.Fatalf("after repair outcome = %s, drift %v", again.Outcome, again.Drift)
				}
				lines := events()
				if d.repaired && markerCount(lines, MarkerRepair) != 1 {
					t.Fatalf("events = %q, want one repair line", lines)
				}
				if !d.repaired && len(lines) != 0 {
					t.Fatalf("events = %q, want none", lines)
				}
			})
		}
	}
}

func TestRepairOwnedObjectRepairsInheritedWriteACL(t *testing.T) {
	enableTestSelfRepair(t)
	events := captureResilienceEvents(t)
	parent := t.TempDir()
	addDarwinACL(t, parent, "everyone allow write,file_inherit")
	path := filepath.Join(parent, "targets.yaml")
	if err := os.WriteFile(path, []byte("x"), 0o640); err != nil {
		t.Fatal(err)
	}
	mustChmod(t, path, 0o640)
	result := RepairOwnedObject(OwnedObject{Path: path, Kind: ObjectAdminFile})
	if result.Outcome != CanonicalRepaired {
		t.Fatalf("outcome = %s, drift %v", result.Outcome, result.Drift)
	}
	lines := events()
	if markerCount(lines, MarkerRepair) != 1 || markerCount(lines, MarkerBoundary) != 1 {
		t.Fatalf("events = %q, want one repair and one boundary line", lines)
	}
}

// Structure is never followed and never fatal: the link target is untouched,
// the entry is moved aside, a directory is recreated, and one boundary line
// is logged.
func TestRepairOwnedObjectNeverFollowsStructure(t *testing.T) {
	cases := []struct {
		name     string
		kind     ObjectKind
		recreate bool
		build    func(t *testing.T, dir, victim, path string)
	}{
		{name: "symlinked directory", kind: ObjectRuntimeDirectory, recreate: true, build: func(t *testing.T, dir, victim, path string) {
			if err := os.Symlink(dir, path); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "symlinked file", kind: ObjectAdminFile, build: func(t *testing.T, dir, victim, path string) {
			if err := os.Symlink(victim, path); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "hard-linked file", kind: ObjectAdminFile, build: func(t *testing.T, dir, victim, path string) {
			if err := os.Link(victim, path); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "file in place of a directory", kind: ObjectAuthorizationDirectory, recreate: true, build: func(t *testing.T, dir, victim, path string) {
			if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			enableTestSelfRepair(t)
			events := captureResilienceEvents(t)
			root := t.TempDir()
			outside := t.TempDir()
			victim := filepath.Join(outside, "victim")
			if err := os.WriteFile(victim, []byte("keep"), 0o666); err != nil {
				t.Fatal(err)
			}
			mustChmod(t, victim, 0o666)
			path := filepath.Join(root, "object")
			tc.build(t, outside, victim, path)

			result := RepairOwnedObject(OwnedObject{Path: path, Kind: tc.kind, MoveAsideStructural: true, Recreate: tc.recreate})
			if info, _ := os.Stat(victim); info.Mode().Perm() != 0o666 {
				t.Fatalf("victim mode changed to %04o", info.Mode().Perm())
			}
			if data, _ := os.ReadFile(victim); string(data) != "keep" {
				t.Fatalf("victim content changed: %q", data)
			}
			if outsideInfo, _ := os.Stat(outside); outsideInfo.Mode().Perm() == 0o750 {
				t.Fatal("the symlinked directory's target was re-stamped")
			}
			moved, _ := filepath.Glob(path + ".defenseclaw-moved-*")
			if len(moved) != 1 {
				t.Fatalf("moved entries = %v, want one", moved)
			}
			if tc.recreate {
				info, err := os.Lstat(path)
				if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
					t.Fatalf("directory was not recreated: %v %v", info, err)
				}
				if result.Outcome != CanonicalRepaired {
					t.Fatalf("outcome = %s, want repaired", result.Outcome)
				}
			} else if _, err := os.Lstat(path); !os.IsNotExist(err) {
				t.Fatalf("structural file still in place: %v", err)
			}
			if got := markerCount(events(), MarkerBoundary); got < 1 {
				t.Fatalf("events = %q, want a boundary line", events())
			}
		})
	}
}

func TestRepairOwnedObjectLeavesStructureWithoutMoveAside(t *testing.T) {
	enableTestSelfRepair(t)
	events := captureResilienceEvents(t)
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("x"), 0o666); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "config.yaml")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	result := RepairOwnedObject(OwnedObject{Path: link, Kind: ObjectConfigFile})
	if result.Outcome != CanonicalStructural {
		t.Fatalf("outcome = %s, want structural", result.Outcome)
	}
	if info, err := os.Lstat(link); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("link was touched: %v", err)
	}
	if markerCount(events(), MarkerBoundary) != 1 {
		t.Fatalf("events = %q", events())
	}
}

func TestRepairOwnedObjectsSkipsChildrenOfStructuralParent(t *testing.T) {
	enableTestSelfRepair(t)
	captureResilienceEvents(t)
	root := t.TempDir()
	outside := t.TempDir()
	child := filepath.Join(outside, "audit.db")
	if err := os.WriteFile(child, []byte("x"), 0o666); err != nil {
		t.Fatal(err)
	}
	mustChmod(t, child, 0o666)
	runtimeDir := filepath.Join(root, "runtime")
	if err := os.Symlink(outside, runtimeDir); err != nil {
		t.Fatal(err)
	}
	results := RepairOwnedObjects([]OwnedObject{
		{Path: runtimeDir, Kind: ObjectRuntimeDirectory},
		{Path: filepath.Join(runtimeDir, "audit.db"), Kind: ObjectRuntimeFile},
	})
	if results[0].Outcome != CanonicalStructural || results[1].Outcome != CanonicalStructural {
		t.Fatalf("outcomes = %s, %s", results[0].Outcome, results[1].Outcome)
	}
	if info, _ := os.Stat(child); info.Mode().Perm() != 0o666 {
		t.Fatalf("a child behind a symlinked folder was repaired: %04o", info.Mode().Perm())
	}
}

func TestRepairOwnedObjectRecreatesMissingDirectory(t *testing.T) {
	enableTestSelfRepair(t)
	events := captureResilienceEvents(t)
	path := filepath.Join(t.TempDir(), "logs")
	result := RepairOwnedObject(OwnedObject{Path: path, Kind: ObjectLogDirectory, Recreate: true})
	if result.Outcome != CanonicalRepaired {
		t.Fatalf("outcome = %s", result.Outcome)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o750 {
		t.Fatalf("recreated directory: %v %v", info, err)
	}
	if markerCount(events(), MarkerRepair) != 1 {
		t.Fatalf("events = %q", events())
	}
}

func TestPinnedManagedServiceLayout(t *testing.T) {
	t.Setenv(DeploymentModeEnv, "")
	if _, ok := PinnedManagedServiceLayout(); ok {
		t.Fatal("layout derived without a managed pin")
	}
	t.Setenv(DeploymentModeEnv, DeploymentModeManagedEnterprise)
	t.Setenv("DEFENSECLAW_HOME", "/opt/cisco/secureclient/defenseclaw")
	t.Setenv(ConfigPathEnv, "/etc/elsewhere/config.yaml")
	t.Setenv(HookGuardianAuthorizationDirEnv, "/opt/cisco/secureclient/defenseclaw/hook-guardian-state")
	layout, ok := PinnedManagedServiceLayout()
	if !ok {
		t.Fatal("layout not derived")
	}
	if layout.ConfigPath != "" {
		t.Fatalf("a config path outside the managed home was accepted: %q", layout.ConfigPath)
	}
	if layout.RuntimeDir != "/opt/cisco/secureclient/defenseclaw/runtime" ||
		layout.ManifestPath != "/opt/cisco/secureclient/defenseclaw/hook-guardian/targets.yaml" ||
		layout.AuthorizationDir != "/opt/cisco/secureclient/defenseclaw/hook-guardian-state" {
		t.Fatalf("layout = %+v", layout)
	}
	t.Setenv("DEFENSECLAW_HOME", "relative/home")
	if _, ok := PinnedManagedServiceLayout(); ok {
		t.Fatal("a relative home was accepted")
	}
}
