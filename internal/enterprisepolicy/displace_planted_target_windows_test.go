//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/legacyconnector"
)

// treeDigest describes everything below root without following a link: each
// entry with its kind, owner and DACL, and for a file its SHA-256. Two equal
// digests mean the same files, the same bytes and the same permissions.
func treeDigest(t *testing.T, root string) string {
	t.Helper()
	var lines []string
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		info, err := entry.Info()
		if err != nil {
			return err
		}
		owner, sd := descriptorOf(t, path)
		line := rel + "|" + info.Mode().String() + "|" + owner.String() + "|" + sd.String()
		if info.Mode().IsRegular() {
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			sum := sha256.Sum256(data)
			line += "|" + hex.EncodeToString(sum[:])
		}
		lines = append(lines, line)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n")
}

// fillJunctionTarget gives a planted junction target known content: files at
// two depths, one with bytes that are not text.
func fillJunctionTarget(t *testing.T, target string) {
	t.Helper()
	nested := filepath.Join(target, "nested")
	userCreatedDir(t, nested)
	for path, body := range map[string][]byte{
		filepath.Join(target, "known.txt"): []byte("a file the user owns\n"),
		filepath.Join(target, "keep.json"): []byte(`{"version":1,"hooks":{}}`),
		filepath.Join(nested, "deep.bin"):  {0x00, 0xff, 0x10, 0x80, 0x7f},
		filepath.Join(nested, "notes.md"):  []byte("# notes\n"),
	} {
		if err := os.WriteFile(path, body, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// GAP-0758 lead ruling 2: displacePlanted removes the junction a standard
// user planted at the Copilot or OpenCode policy folder, never what it points
// at. The target keeps the same files, the same bytes and the same
// permissions, whether displacePlanted is called on its own or reached from
// the connector reconcile.
func TestWindowsDisplacePlantedLeavesTheJunctionTargetUntouched(t *testing.T) {
	for _, part := range []string{`GitHub\Copilot`, "opencode"} {
		for _, via := range []string{"displacePlanted", "reconcile"} {
			t.Run(strings.ReplaceAll(part, `\`, "-")+"/"+via, func(t *testing.T) {
				opts := windowsOpenCodeTestOptions(t)
				planted := filepath.Join(opts.WindowsProgramData, part)
				if parent := filepath.Dir(planted); parent != opts.WindowsProgramData {
					if _, err := ensurePolicyDir(opts, parent); err != nil {
						t.Fatal(err)
					}
				}
				target := plantAsUser(t, planted, "junction")
				fillJunctionTarget(t, target)
				before := treeDigest(t, target)
				if !strings.Contains(before, "known.txt") || !strings.Contains(before, "deep.bin") {
					t.Fatalf("test setup: the target digest misses its files:\n%s", before)
				}

				switch via {
				case "displacePlanted":
					note, err := displacePlanted(opts, planted)
					if err != nil || !strings.Contains(note, "its target is untouched") {
						t.Fatalf("displacePlanted: %q %v", note, err)
					}
					if _, err := os.Lstat(planted); !errors.Is(err, os.ErrNotExist) {
						t.Fatalf("the junction must be gone: %v", err)
					}
				case "reconcile":
					if part == "opencode" {
						if _, err := PublishWindowsGoOwned(opts, []string{ConnectorOpenCode}); err != nil {
							t.Fatalf("a planted junction must not block OpenCode: %v", err)
						}
					} else if _, err := (copilotTarget{}).Reconcile(opts); err != nil {
						t.Fatalf("a planted junction must not block Copilot: %v", err)
					}
					// DefenseClaw protected folder, not the junction, is at the path now.
					requireProtected(t, planted)
				}
				if after := treeDigest(t, target); after != before {
					t.Fatalf("the junction target changed:\nbefore:\n%s\nafter:\n%s", before, after)
				}
			})
		}
	}
}

// An administrator-made junction is not a standard user plant: displacePlanted
// refuses it by design, and the refusal leaves the link and its target alone.
func TestWindowsDisplacePlantedRefusalLeavesAnAdministratorJunctionTargetUntouched(t *testing.T) {
	opts := windowsTestOptions(t)
	target := filepath.Join(filepath.Dir(opts.WindowsProgramData), "admin-target")
	userCreatedDir(t, target)
	fillJunctionTarget(t, target)
	link := filepath.Join(opts.WindowsProgramData, "opencode")
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		t.Skipf("mklink /J unavailable: %v %s", err, out)
	}
	ownAs(t, link, wellKnownSID(t, windows.WinBuiltinAdministratorsSid))
	before := treeDigest(t, target)
	if _, err := displacePlanted(opts, link); !errors.Is(err, errOwnedByAdministrator) {
		t.Fatalf("an administrator junction must be refused, got %v", err)
	}
	if _, err := os.Lstat(link); err != nil {
		t.Fatalf("the administrator junction must stay: %v", err)
	}
	if after := treeDigest(t, target); after != before {
		t.Fatalf("the junction target changed:\nbefore:\n%s\nafter:\n%s", before, after)
	}
}

// GAP-0758 review S1: the teardown of the Go-owned vendor policy takes no part
// in the install-side take-back. A link a standard user planted at a vendor
// folder is removed, the link only, and no protected folder is created in its
// place; a link an administrator made is kept and named, and the removal
// neither fails on it nor reads through it. Either way the target keeps its
// files and bytes.
func TestWindowsGoOwnedRemovalKeepsOrClearsALinkAndCreatesNothing(t *testing.T) {
	for _, part := range []string{`GitHub\Copilot`, "opencode"} {
		for _, owner := range []string{"standard user", "administrator"} {
			t.Run(strings.ReplaceAll(part, `\`, "-")+"/"+owner, func(t *testing.T) {
				opts := windowsOpenCodeTestOptions(t)
				planted := filepath.Join(opts.WindowsProgramData, part)
				if parent := filepath.Dir(planted); parent != opts.WindowsProgramData {
					if _, err := ensurePolicyDir(opts, parent); err != nil {
						t.Fatal(err)
					}
				}
				target := filepath.Join(filepath.Dir(opts.WindowsProgramData), "link-target")
				userCreatedDir(t, target)
				fillJunctionTarget(t, target)
				if out, err := exec.Command("cmd", "/c", "mklink", "/J", planted, target).CombinedOutput(); err != nil {
					t.Skipf("mklink /J unavailable: %v %s", err, out)
				}
				var sid windows.WELL_KNOWN_SID_TYPE = windows.WinBuiltinUsersSid
				if owner == "administrator" {
					sid = windows.WinBuiltinAdministratorsSid
				}
				ownAs(t, planted, wellKnownSID(t, sid))
				before := treeDigest(t, target)

				result, err := RemoveWindowsGoOwned(opts)
				if err != nil {
					t.Fatalf("a link at %s must not fail the removal: %v", part, err)
				}
				_, lerr := os.Lstat(planted)
				switch owner {
				case "administrator":
					if lerr != nil {
						t.Fatalf("an administrator link must be kept: %v", lerr)
					}
					if kept := WindowsGoOwnedLinkedFolders(opts); len(kept) != 1 || !strings.EqualFold(kept[0], planted) {
						t.Fatalf("the kept link must be named once: %v", kept)
					}
				case "standard user":
					if !os.IsNotExist(lerr) {
						t.Fatalf("the user link must be removed and nothing created in its place: %v", lerr)
					}
					if kept := WindowsGoOwnedLinkedFolders(opts); len(kept) != 0 {
						t.Fatalf("no link is left to name: %v", kept)
					}
				}
				if len(result.States) == 0 {
					t.Fatal("the removal must say what it did with the link")
				}
				if after := treeDigest(t, target); after != before {
					t.Fatalf("the link target changed:\nbefore:\n%s\nafter:\n%s", before, after)
				}
			})
		}
	}
}

// GAP-0758 review S2: Devin Cascade has two policy files in two folders
// (ProgramData\Devin and the pre-rename folder, legacyconnector.CascadeMachineFolder). An administrator
// link at one of them keeps that folder alone: nothing is read through the link
// and its target is unchanged, while DefenseClaw's entry in the other folder
// is still removed, so a Cascade registration does not keep refusing after the
// uninstall.
func TestWindowsGoOwnedRemovalKeepsOnlyTheLinkedDevinFolder(t *testing.T) {
	for _, linked := range []string{"Devin", legacyconnector.CascadeMachineFolder} {
		t.Run(linked+" linked", func(t *testing.T) {
			opts := windowsOpenCodeTestOptions(t)
			devinPath, err := DevinSystemHooksPath(opts)
			if err != nil {
				t.Fatal(err)
			}
			legacyPath, err := devinCascadeLegacyHooksPath(opts)
			if err != nil {
				t.Fatal(err)
			}
			// Releases 1.0.5 to 1.0.8 wrote DefenseClaw's Cascade refusal into
			// both files, after an administrator's own content. DefenseClaw
			// publishes nothing now and only withdraws it, so the upgrade case
			// is planted as that release left it.
			for _, path := range []string{devinPath, legacyPath} {
				if err := createProtectedDir(filepath.Dir(path)); err != nil {
					t.Fatal(err)
				}
				planted := earlierReleaseCascadeFile(t, opts, path, `{"version":1,"hooks":{}}`)
				if err := os.WriteFile(path, []byte(planted), 0o644); err != nil {
					t.Fatal(err)
				}
				// DefenseClaw's own writer left these files owned by the
				// Administrators group; the withdrawal refuses a file whose
				// owner is not trusted, so the planted file carries that owner.
				ownAs(t, path, wellKnownSID(t, windows.WinBuiltinAdministratorsSid))
			}
			owned := func(path string) bool {
				t.Helper()
				data, err := os.ReadFile(path)
				if os.IsNotExist(err) {
					return false
				}
				if err != nil {
					t.Fatal(err)
				}
				_, has, err := stripDevinCascadeHooks(opts)(data)
				if err != nil {
					t.Fatal(err)
				}
				return has
			}
			if !owned(devinPath) || !owned(legacyPath) {
				t.Fatalf("test setup: DefenseClaw's entry is missing (Devin %t, legacy %t)", owned(devinPath), owned(legacyPath))
			}
			linkedPath, otherPath := devinPath, legacyPath
			if linked == legacyconnector.CascadeMachineFolder {
				linkedPath, otherPath = legacyPath, devinPath
			}
			linkFolder := filepath.Dir(linkedPath)
			content, err := os.ReadFile(linkedPath)
			if err != nil {
				t.Fatal(err)
			}
			// The folder becomes an administrator junction to a target that
			// holds a file with DefenseClaw's own entry.
			if err := os.Rename(linkFolder, linkFolder+".moved"); err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(filepath.Dir(opts.WindowsProgramData), "devin-link-target")
			userCreatedDir(t, target)
			if err := os.WriteFile(filepath.Join(target, "hooks.json"), content, 0o644); err != nil {
				t.Fatal(err)
			}
			if out, err := exec.Command("cmd", "/c", "mklink", "/J", linkFolder, target).CombinedOutput(); err != nil {
				t.Skipf("mklink /J unavailable: %v %s", err, out)
			}
			ownAs(t, linkFolder, wellKnownSID(t, windows.WinBuiltinAdministratorsSid))
			before := treeDigest(t, target)

			result, err := RemoveWindowsGoOwned(opts)
			if err != nil {
				t.Fatalf("a link at %s must not fail the removal: %v", linkFolder, err)
			}
			if owned(otherPath) {
				t.Fatalf("DefenseClaw's entry at %s was left behind a link at %s", otherPath, linkFolder)
			}
			if _, err := os.Lstat(linkFolder); err != nil {
				t.Fatalf("the administrator link must stay: %v", err)
			}
			if after := treeDigest(t, target); after != before {
				t.Fatalf("the link target changed:\nbefore:\n%s\nafter:\n%s", before, after)
			}
			if kept := WindowsGoOwnedLinkedFolders(opts); len(kept) != 1 || !strings.EqualFold(kept[0], linkFolder) {
				t.Fatalf("the kept link must be named once: %v", kept)
			}
			if len(result.States) == 0 {
				t.Fatal("the removal must say what it did")
			}
		})
	}
}
