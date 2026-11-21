// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hermesskills

import (
	"encoding/json"
	"flag"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// scripts/hermes_vendor_plugin_digests.py runs TestGenerateHermesVendorSkillDigests
// with these flags to regenerate vendor_digests.go. The digests come from the
// code that decides admission (readSkillName and treeSHA256), so they are the
// digests the gateway computes.
var (
	hermesVendorTrees = flag.String("hermes-vendor-trees", "",
		"folder with one release checkout per Hermes release: <release>/hermes-agent/skills")
	hermesVendorOut = flag.String("hermes-vendor-out", "",
		"JSON file the bundled-skill digests of every release are written to")
)

// TestGenerateHermesVendorSkillDigests lists the bundled skills of every
// release checkout under -hermes-vendor-trees as Discover does (every folder
// with a SKILL.md, below the skills root) and writes {release: {skill:
// digest}} to -hermes-vendor-out. A skill whose tree cannot be verified (a
// link, a special file, an oversize tree) or whose name differs from its
// folder (admission refuses it whatever its digest) gets an empty digest: no
// copy of it can match, so the tool leaves it out. Without the flags the test
// is skipped.
func TestGenerateHermesVendorSkillDigests(t *testing.T) {
	if *hermesVendorTrees == "" || *hermesVendorOut == "" {
		t.Skip("run by scripts/hermes_vendor_plugin_digests.py")
	}
	releases, err := os.ReadDir(*hermesVendorTrees)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]map[string]string{}
	for _, release := range releases {
		if !release.IsDir() {
			continue
		}
		root := filepath.Join(*hermesVendorTrees, release.Name(), "hermes-agent", "skills")
		digests := map[string]string{}
		err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if !entry.IsDir() || samePath(path, root) {
				return nil
			}
			name, ok := readSkillName(path)
			if !ok {
				return nil
			}
			relative, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			key := filepath.ToSlash(relative)
			digests[key] = ""
			if name != filepath.Base(relative) {
				t.Logf("release %s: %s is named %q, admission never matches it", release.Name(), key, name)
				return nil
			}
			digest, err := treeSHA256(path)
			if err != nil {
				t.Logf("release %s: %s cannot be verified: %v", release.Name(), key, err)
				return nil
			}
			digests[key] = digest
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(digests) == 0 {
			t.Fatalf("release %s: no bundled skills under %s", release.Name(), root)
		}
		out[release.Name()] = digests
	}
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(*hermesVendorOut, append(data, 10), 0o600); err != nil {
		t.Fatal(err)
	}
}
