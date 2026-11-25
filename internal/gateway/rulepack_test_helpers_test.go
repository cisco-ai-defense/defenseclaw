// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	policyassets "github.com/defenseclaw/defenseclaw/policies"
)

func mustLoadRulePack(t testing.TB, dir string) *guardrail.RulePack {
	t.Helper()
	rp, err := guardrail.LoadRulePack(dir)
	if err != nil {
		t.Fatalf("LoadRulePack(%q): %v", dir, err)
	}
	return rp
}

func invalidRulePackDir(t testing.TB) string {
	t.Helper()
	dir := t.TempDir()
	writeRulePackFixtureFile(t, dir, "suppressions.yaml", "version: [\n")
	return dir
}

func writeRulePackFixtureFile(t testing.TB, root, relative, contents string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("create rule-pack fixture directory: %v", err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write rule-pack fixture %q: %v", relative, err)
	}
}

// installDefaultRulePackForDataDir writes the embedded default rule pack to
// <dataDir>/policies/guardrail/default and returns that folder. It reads the
// pack from the policies package's embedded files, not from the source tree:
// a test executable built on another machine (the native Windows harness
// builds on Linux) has no source tree at the path the build recorded.
func installDefaultRulePackForDataDir(t testing.TB, dataDir string) string {
	t.Helper()
	files, err := policyassets.Files()
	if err != nil {
		t.Fatalf("list the embedded default rule pack: %v", err)
	}
	destination := filepath.Join(dataDir, "policies", "guardrail", "default")
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		t.Fatalf("create test rule-pack parent: %v", err)
	}
	copied := 0
	for _, file := range files {
		relative, ok := strings.CutPrefix(file.Path, "guardrail/default/")
		if !ok {
			continue
		}
		writeRulePackFixtureFile(t, destination, relative, string(file.Data))
		copied++
	}
	if copied == 0 {
		t.Fatal("the embedded default rule pack lists no files")
	}
	return destination
}

func routerWithDefaultRulePack(t testing.TB) *EventRouter {
	t.Helper()
	router := NewEventRouter(nil, nil, nil, false)
	router.generationSource = staticRulePackGeneration(mustLoadRulePack(t, ""))
	return router
}

// staticRulePackGeneration gives a test router a fixed, unpublished
// generation whose active rule pack is pack.
func staticRulePackGeneration(pack *guardrail.RulePack) func() *Generation {
	g := &Generation{active: pack}
	return func() *Generation { return g }
}
