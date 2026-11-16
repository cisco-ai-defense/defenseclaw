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

package enterprisehooks

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// folderDigest lists everything below root, without following a link, with
// each file SHA-256: equal digests mean the same names and the same bytes.
func folderDigest(t *testing.T, root string) string {
	t.Helper()
	var lines []string
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		line := rel
		if entry.Type().IsRegular() {
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			sum := sha256.Sum256(data)
			line += " " + hex.EncodeToString(sum[:])
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

// GAP-0758 review S5: the classifier against a real junction, not an injected
// probe. A junction at the folder and a path below it are kept; a plain
// folder, an absent one and a file are classified as before; and DefenseClaw
// named decoys in the junction target are neither read nor changed nor joined
// by a new file.
func TestManagedPolicyDirectoryClassifierMeetsARealJunction(t *testing.T) {
	previousStandalone := windowsEnterpriseStandaloneProcess
	t.Cleanup(func() { windowsEnterpriseStandaloneProcess = previousStandalone })
	windowsEnterpriseStandaloneProcess = func() bool { return true }
	windowsManagedPolicyKept.Lock()
	windowsManagedPolicyKept.paths = map[string]string{}
	windowsManagedPolicyKept.Unlock()
	t.Cleanup(func() {
		windowsManagedPolicyKept.Lock()
		windowsManagedPolicyKept.paths = map[string]string{}
		windowsManagedPolicyKept.Unlock()
	})

	base := t.TempDir()
	target := filepath.Join(base, "target")
	if err := os.MkdirAll(filepath.Join(target, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		".defenseclaw-managed-runtime-selector.state",
		".defenseclaw-managed-runtime-selector.lock",
		".defenseclaw-managed-hooks.state",
		"defenseclaw-hook.ps1",
		"90-defenseclaw.json",
	} {
		if err := os.WriteFile(filepath.Join(target, name), []byte("decoy "+name), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	before := folderDigest(t, target)
	plain := filepath.Join(base, "plain")
	if err := os.Mkdir(plain, 0o755); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(base, "file.txt")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	makeTestJunction(t, link, target)
	t.Cleanup(func() { _ = os.Remove(link) })

	for _, row := range []struct {
		name string
		path string
		want windowsManagedPolicyDirState
		kept string
	}{
		{"absent", filepath.Join(base, "absent"), windowsManagedPolicyDirAbsent, ""},
		{"plain", plain, windowsManagedPolicyDirPlain, ""},
		{"file", file, windowsManagedPolicyDirKept, file},
		{"junction", link, windowsManagedPolicyDirKept, link},
		{"below the junction", filepath.Join(link, "sub"), windowsManagedPolicyDirKept, link},
		{"absent below the junction", filepath.Join(link, "missing", "deeper"), windowsManagedPolicyDirKept, link},
	} {
		state, kept, err := inspectWindowsManagedPolicyDirectoryNoFollow(row.path)
		if err != nil || state != row.want || !strings.EqualFold(kept, row.kept) {
			t.Errorf("%s: state=%v kept=%q err=%v, want state=%v kept=%q", row.name, state, kept, err, row.want, row.kept)
		}
	}
	if keptNow, err := windowsManagedPolicyLinkKept(filepath.Join(link, "sub")); err != nil || !keptNow {
		t.Errorf("the teardown state below a junction: kept=%v err=%v", keptNow, err)
	}
	if after := folderDigest(t, target); after != before {
		t.Fatalf("the junction target changed:\nbefore:\n%s\nafter:\n%s", before, after)
	}
	if _, err := os.Lstat(link); err != nil {
		t.Fatalf("the junction itself must stay: %v", err)
	}
}
