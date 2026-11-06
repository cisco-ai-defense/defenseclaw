// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package guardrail

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// stockProfileDigest is cli/defenseclaw/guardrail_profiles.profile_digest:
// sha256 over "<relative path>\x00<sha256 hex of the file>\n" for every
// file of the profile in path order, dot files and __pycache__ left out.
func stockProfileDigest(t *testing.T, root string) string {
	t.Helper()
	files := map[string][]byte{}
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil || rel == "." {
			return err
		}
		for _, part := range strings.Split(filepath.ToSlash(rel), "/") {
			if strings.HasPrefix(part, ".") || part == "__pycache__" {
				if entry.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
		}
		if entry.Type().IsRegular() {
			content, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			files[filepath.ToSlash(rel)] = content
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	digest := sha256.New()
	for _, name := range names {
		sum := sha256.Sum256(files[name])
		digest.Write([]byte(name + "\x00" + hex.EncodeToString(sum[:]) + "\n"))
	}
	return hex.EncodeToString(digest.Sum(nil))
}

// TestBundledProfilesAreListedAsStock fails when a bundled rule pack
// changes and STOCK_PROFILE_DIGESTS in cli/defenseclaw/guardrail_profiles.py
// does not list its new digest: an upgrade would then treat a pack seeded
// from this build as operator-edited and never refresh it (gx052 review N2).
// It is the Go-side twin of cli/tests/test_guardrail_profiles.py
// test_bundled_profiles_are_listed_as_stock, so the Go gates of a pack
// change catch it too. Print the digests with
// python -m defenseclaw.guardrail_profiles.
func TestBundledProfilesAreListedAsStock(t *testing.T) {
	source, err := os.ReadFile(filepath.Join("..", "..", "cli", "defenseclaw", "guardrail_profiles.py"))
	if err != nil {
		t.Fatal(err)
	}
	for _, profile := range []string{"default", "permissive", "strict"} {
		block := regexp.MustCompile(`(?s)"` + profile + `": frozenset\(\s*\{(.*?)\}\s*\)`).FindSubmatch(source)
		if block == nil {
			t.Fatalf("STOCK_PROFILE_DIGESTS has no %s entry", profile)
		}
		digest := stockProfileDigest(t, filepath.Join("..", "..", "policies", "guardrail", profile))
		if !strings.Contains(string(block[1]), `"`+digest+`"`) {
			t.Errorf("bundled %s pack digest %s is not in STOCK_PROFILE_DIGESTS; add it (python -m defenseclaw.guardrail_profiles)", profile, digest)
		}
	}
}
