// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"os"
	"path/filepath"
	"testing"
)

// GAP-1404: each lifecycle result write stages in its own exclusively
// created file. With one shared path+".tmp", a run that finished while
// another was still staging overwrote that run's staging file and renamed
// it into place, so either run could publish the other's bytes.
func TestWriteFileKeepingDACLDoesNotShareAStagingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "lifecycle-result.json")
	sibling := filepath.Join(dir, "deployment.json")
	for name, body := range map[string]string{path: "{}\n", sibling: "{}\n"} {
		if err := os.WriteFile(name, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// Another run's write is staged and not yet renamed.
	other := path + ".tmp"
	if err := os.WriteFile(other, []byte("{\"run\":\"other\"}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	const mine = "{\"run\":\"this\"}\n"
	if err := writeFileKeepingDACL(path, []byte(mine), sibling); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != mine {
		t.Fatalf("published %q, %v, want this run's bytes", got, err)
	}
	if got, err := os.ReadFile(other); err != nil || string(got) != "{\"run\":\"other\"}\n" {
		t.Fatalf("the other run's staging file = %q, %v, want it untouched", got, err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		names := []string{}
		for _, entry := range entries {
			names = append(names, entry.Name())
		}
		t.Fatalf("directory holds %q, want the result, its sibling and the other run's staging file only", names)
	}
}
