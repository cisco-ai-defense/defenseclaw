// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// rel-1-0-10:GAP-1668. A recursive search looked up every first segment of
// the credentials table (about 42) under each folder it names, again for a
// folder named again, so grep -r K . . . ... cost N x 42 lookups. A folder is
// probed once per call now; a folder named again finds the same files.
func TestGAP1668RepeatedSearchFolderIsProbedOnce(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".aws"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".aws", "credentials"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	segments := len(credentialProbeFirstSegments())
	// Work for one folder's probes and the words, not for 200 of them.
	limits := defaultCredentialPathLimits
	limits.work = 20 * segments
	command := "grep -rn TODO" + strings.Repeat(" .", 200)
	out := parsePOSIX(command, 1, 0)
	classifyOutput(&out)
	record := resolveCredentialPathReadsWithin(NewCredentialWalkBudget(context.Background()), limits, out.credentialWords, dir, dir, out.commands, out.paths)
	if record == nil {
		t.Fatal("no record: the credentials file under the searched folder was not found")
	}
	if record.caps.Any() {
		t.Fatalf("grep -r over one folder named 200 times hit a cap (%s): each name probed the folder again", record.caps.Reason())
	}
	found := false
	for _, read := range record.reads {
		spelled := read.Resolved
		if spelled == "" {
			spelled = read.Value
		}
		found = found || strings.HasSuffix(spelled, filepath.Join(".aws", "credentials"))
	}
	if !found {
		t.Fatalf("the credentials file under the searched folder is not found: %+v", record)
	}
}

// rel-1-0-10:GAP-1668, spelling variants. The dedupe of a folder named again
// is keyed on the cleaned folder, not its spelling: ./ ././ ... (20
// spellings of one folder) cost one folder's probes, not 20.
func TestGAP1668SpellingsOfOneFolderAreProbedOnce(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".aws"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".aws", "credentials"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	segments := len(credentialProbeFirstSegments())
	limits := defaultCredentialPathLimits
	limits.work = 20 * segments
	var spellings []string
	for i := 1; i <= 20; i++ {
		spellings = append(spellings, strings.Repeat("./", i))
	}
	command := "grep -rn TODO " + strings.Join(spellings, " ")
	out := parsePOSIX(command, 1, 0)
	classifyOutput(&out)
	record := resolveCredentialPathReadsWithin(NewCredentialWalkBudget(context.Background()), limits, out.credentialWords, dir, dir, out.commands, out.paths)
	if record == nil {
		t.Fatal("no record: the credentials file under the searched folder was not found")
	}
	if record.caps.Any() {
		t.Fatalf("grep -r over %d spellings of one folder hit a cap (%s): each spelling probed the folder again", len(spellings), record.caps.Reason())
	}
	found := 0
	for _, read := range record.reads {
		spelled := read.Resolved
		if spelled == "" {
			spelled = read.Value
		}
		if strings.HasSuffix(spelled, filepath.Join(".aws", "credentials")) {
			found++
		}
	}
	if found == 0 {
		t.Fatalf("the credentials file under the searched folder is not found: %+v", record)
	}
}
