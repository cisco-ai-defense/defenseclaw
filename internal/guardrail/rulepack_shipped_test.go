// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package guardrail

import (
	"os"
	"path/filepath"
	"testing"
)

// TestShippedRulePackFilesDigestIsTheLoadedPack covers #1445: the digest the
// gateway expects of a shipped folder is the FilesDigest the loader computes
// for a folder holding exactly the release's pack, and an edited file
// changes it.
func TestShippedRulePackFilesDigestIsTheLoadedPack(t *testing.T) {
	for _, name := range []string{"strict", "permissive"} {
		want, err := ShippedRulePackFilesDigest(name)
		if err != nil {
			t.Fatal(err)
		}
		src := filepath.Join("..", "..", "policies", "guardrail", name)
		pack, err := LoadRulePack(src)
		if err != nil {
			t.Fatalf("load %s: %v", src, err)
		}
		if got := pack.FilesDigest(); got != want {
			t.Fatalf("%s: loaded FilesDigest %s, ShippedRulePackFilesDigest %s", name, got, want)
		}
		edited := t.TempDir()
		if err := os.CopyFS(edited, os.DirFS(src)); err != nil {
			t.Fatal(err)
		}
		suppressions := filepath.Join(edited, "suppressions.yaml")
		raw, err := os.ReadFile(suppressions)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(suppressions, append(raw, []byte("\n# edited\n")...), 0o600); err != nil {
			t.Fatal(err)
		}
		changed, err := LoadRulePack(edited)
		if err != nil {
			t.Fatal(err)
		}
		if changed.FilesDigest() == want {
			t.Fatalf("%s: an edited copy has the shipped digest", name)
		}
	}
	if _, err := ShippedRulePackFilesDigest("default"); err == nil {
		t.Fatal("default is embedded, not shipped as a folder")
	}
}
