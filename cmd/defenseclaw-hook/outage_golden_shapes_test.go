// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

// The config shapes of the outage-mode golden (rel-1-0-10:GAP-0603). This
// file uses the standard library only: the golden was recorded by copying it
// into the full-CLI tree (rel/1.0.10 9efb4f1799, package internal/cli) and
// running it against that hookOutageFailModeNow, so both binaries decide the
// same table.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

type outageShape struct {
	Name, Connector, Config string
	// NoConfig writes no config.yaml at all.
	NoConfig bool
}

type outageResult struct {
	Name string `json:"name"`
	Mode string `json:"mode"`
}

const outageBase = "config_version: 9\nobservability: {}\nguardrail:\n  mode: action\n"

func outageCustom(name, pack, pin string) string {
	return fmt.Sprintf("  rule_pack: %s\n  custom_packs:\n    %s:\n      path: {{PACK:%s}}\n      digest: %s\n", name, name, pack, pin)
}

func outageShapes() []outageShape {
	return []outageShape{
		{Name: "default pack", Connector: "codex", Config: outageBase},
		{Name: "observe mode, default pack", Connector: "claudecode", Config: "config_version: 9\nobservability: {}\nguardrail:\n  mode: observe\n"},
		{Name: "permissive pack", Connector: "claudecode", Config: outageBase + "  rule_pack: permissive\n"},
		{Name: "strict pack", Connector: "codex", Config: outageBase + "  rule_pack: strict\n"},
		{Name: "saved closed", Connector: "codex", Config: outageBase + "  hook_fail_mode: closed\n"},
		{Name: "saved open over strict", Connector: "codex", Config: outageBase + "  rule_pack: strict\n  hook_fail_mode: open\n"},
		{Name: "connector strict pack", Connector: "codex", Config: outageBase + "  connectors:\n    codex:\n      rule_pack: strict\n"},
		{Name: "pinned custom default pack", Connector: "codex", Config: outageBase + outageCustom("operator", "default", "{{PIN:default}}")},
		{Name: "pinned custom default pack, other connector", Connector: "claudecode", Config: outageBase + outageCustom("operator", "default", "{{PIN:default}}")},
		{Name: "pinned custom permissive pack", Connector: "claudecode", Config: outageBase + outageCustom("operator", "permissive", "{{PIN:permissive}}")},
		{Name: "pinned custom strict pack", Connector: "codex", Config: outageBase + outageCustom("operator", "strict", "{{PIN:strict}}")},
		{Name: "pinned custom pack, stale pin", Connector: "codex", Config: outageBase + outageCustom("operator", "default", "sha256:"+strings.Repeat("1", 64))},
		{Name: "pinned custom pack, expression does not compile", Connector: "codex", Config: outageBase + outageCustom("operator", "bad-cel", "{{PIN:bad-cel}}")},
		{Name: "unpinned custom default pack", Connector: "codex", Config: outageBase + "  rule_pack: operator\n  custom_packs:\n    operator:\n      path: {{PACK:default}}\n"},
		{Name: "connector custom pinned default pack", Connector: "codex", Config: outageBase + "  custom_packs:\n    operator:\n      path: {{PACK:default}}\n      digest: {{PIN:default}}\n  connectors:\n    codex:\n      rule_pack: operator\n"},
		{Name: "sandbox profile pack looser than the admin floor", Connector: "codex", Config: outageBase + "  profiles:\n    contractors:\n      sandbox:\n        required_pack: open\nopenshell:\n  admin:\n    required_pack: balanced\n"},
		{Name: "managed deployment", Connector: "codex", Config: "config_version: 9\ndeployment_mode: managed_enterprise\nobservability: {}\nguardrail:\n  mode: action\n"},
		{Name: "unreadable config", Connector: "codex", Config: "config_version: 9\nguardrail: [\n"},
		{Name: "no config", Connector: "codex", NoConfig: true},
	}
}

// outagePackDigest is the FilesDigest pin of a fixture pack: every file of
// the folder, by slash path, as the rule loader hashes the files it loads.
func outagePackDigest(t *testing.T, dir string) string {
	t.Helper()
	sums := map[string]string{}
	err := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(body)
		sums[filepath.ToSlash(rel)] = hex.EncodeToString(sum[:])
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	rels := make([]string, 0, len(sums))
	for rel := range sums {
		rels = append(rels, rel)
	}
	sort.Strings(rels)
	h := sha256.New()
	for _, rel := range rels {
		fmt.Fprintf(h, "%s\n%s\n", rel, sums[rel])
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// runOutageShapes decides every shape with outage (the outage mode of a
// per-user hook whose hooks folder is given) in a fresh account home.
func runOutageShapes(t *testing.T, packs string, outage func(connector, hookDir string) string) []outageResult {
	t.Helper()
	var results []outageResult
	for _, shape := range outageShapes() {
		home := t.TempDir()
		t.Setenv("DEFENSECLAW_HOME", home)
		t.Setenv("HOME", home)
		t.Setenv("USERPROFILE", home)
		t.Setenv("DEFENSECLAW_CONFIG", "")
		body := shape.Config
		for _, pack := range []string{"default", "permissive", "strict", "bad-cel"} {
			dir := filepath.Join(t.TempDir(), "pack-"+pack)
			if err := os.CopyFS(dir, os.DirFS(filepath.Join(packs, pack))); err != nil {
				t.Fatal(err)
			}
			body = strings.ReplaceAll(body, "{{PACK:"+pack+"}}", fmt.Sprintf("%q", dir))
			body = strings.ReplaceAll(body, "{{PIN:"+pack+"}}", outagePackDigest(t, dir))
		}
		if err := os.MkdirAll(filepath.Join(home, "hooks"), 0o700); err != nil {
			t.Fatal(err)
		}
		if !shape.NoConfig {
			if err := os.WriteFile(filepath.Join(home, "config.yaml"), []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		results = append(results, outageResult{Name: shape.Name, Mode: outage(shape.Connector, filepath.Join(home, "hooks"))})
	}
	return results
}
