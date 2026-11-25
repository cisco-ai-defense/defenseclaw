// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// rel-1-0-10:GAP-1045. A recursive search over many folders took one lookup
// per folder plus one per first segment of the credentials table (about 42)
// whether or not the segment exists, so a grep -r over 25+ folders of a
// monorepo hit the lookup cap (TRUNCATED: alert, block in strict) though it
// read nothing secret. Only the first segments that exist cost a lookup now.
func TestGAP1045RecursiveSearchOverManyFoldersStaysUnderTheCaps(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte(t.Name()), 0o600); err != nil {
		t.Fatal(err)
	}
	var folders []string
	for i := 0; i < 60; i++ {
		name := fmt.Sprintf("mod%02d", i)
		if err := os.MkdirAll(filepath.Join(dir, name), 0o700); err != nil {
			t.Fatal(err)
		}
		folders = append(folders, name)
	}
	command := "sed -n p .env; grep -rn TODO " + strings.Join(folders, " ")
	out := parsePOSIX(command, 1, 0)
	classifyOutput(&out)
	record := resolveCredentialPathReadsWithin(NewCredentialWalkBudget(context.Background()), defaultCredentialPathLimits, out.credentialWords, dir, dir, out.commands, out.paths)
	if record == nil || record.caps.Has(bounded.Paths) {
		t.Fatalf("grep -rn over %d existing folders hit the lookup cap: %+v", len(folders), record)
	}
	// A credentials file in one of the folders is still found.
	if err := os.MkdirAll(filepath.Join(dir, "mod07", ".aws"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "mod07", ".aws", "credentials"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	record = resolveCredentialPathReadsWithin(NewCredentialWalkBudget(context.Background()), defaultCredentialPathLimits, out.credentialWords, dir, dir, out.commands, out.paths)
	// A Windows host records the probed file by its native path (Value): a
	// POSIX read carries no Resolved spelling of a drive-letter path.
	found := false
	for _, read := range record.reads {
		spelled := read.Resolved
		if spelled == "" {
			spelled = read.Value
		}
		found = found || strings.HasSuffix(spelled, filepath.Join("mod07", ".aws", "credentials"))
	}
	if !found {
		t.Fatalf("the credentials file under a searched folder is no longer found: %+v", record)
	}
}
