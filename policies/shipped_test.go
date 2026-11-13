// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package policyassets

import (
	"regexp"
	"strings"
	"testing"
)

// TestShippedRulePackFiles covers #1445: the managed Windows Setup ships the
// strict and permissive packs, every file of both, and names their folder by
// a digest of exactly those files.
func TestShippedRulePackFiles(t *testing.T) {
	files, err := ShippedRulePackFiles()
	if err != nil {
		t.Fatal(err)
	}
	all, err := Files()
	if err != nil {
		t.Fatal(err)
	}
	want := 0
	for _, file := range all {
		if strings.HasPrefix(file.Path, "guardrail/strict/") || strings.HasPrefix(file.Path, "guardrail/permissive/") {
			want++
		}
	}
	if len(files) == 0 || len(files) != want {
		t.Fatalf("shipped files = %d, want the %d files of guardrail/strict and guardrail/permissive", len(files), want)
	}
	packs := map[string]bool{}
	for _, file := range files {
		pack, rest, ok := strings.Cut(file.Path, "/")
		if !ok || rest == "" || !IsShippedRulePack(pack) {
			t.Fatalf("shipped file %q is not under strict/ or permissive/", file.Path)
		}
		packs[pack] = true
	}
	if !packs["strict"] || !packs["permissive"] || IsShippedRulePack("default") {
		t.Fatalf("shipped packs = %v; default must stay embedded", packs)
	}
	digest, err := ShippedRulePackDigest()
	if err != nil || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(digest) {
		t.Fatalf("digest = %q, %v", digest, err)
	}
	if again, _ := ShippedRulePackDigest(); again != digest {
		t.Fatalf("digest is not stable: %s then %s", digest, again)
	}
	name, err := ShippedRulePackFolderName()
	if err != nil || name != digest[:16] {
		t.Fatalf("folder name = %q, %v; want %s", name, err, digest[:16])
	}
}
